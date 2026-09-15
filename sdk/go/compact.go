package microsandbox

import (
	"context"
	"encoding/json"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// DiskCompactionOptions selects explicit maintenance, never persisted desired configuration.
type DiskCompactionOptions struct {
	// Layers limits the oldest sealed physical layers per disk including the base, excluding the writable head.
	// Nil selects all sealed layers; the limit must be at least two. Chains with fewer than two sealed layers are skipped.
	Layers *uint32 `json:"layers,omitempty"`
	DryRun bool    `json:"dry_run,omitempty"`
	// Disk selects one owned disk by guest path; "/" selects the root. Conflicts with RootDiskOnly.
	Disk string `json:"disk,omitempty"`
	// RootDiskOnly excludes owned data disks. Conflicts with Disk.
	RootDiskOnly bool `json:"root_disk_only,omitempty"`
}

// DiskCompactionDiskResult reports one selected disk, including unchanged short chains.
type DiskCompactionDiskResult struct {
	GuestPath         string `json:"guest_path"`
	InputLayers       uint32 `json:"input_layers"`
	SelectedLayers    uint32 `json:"selected_layers"`
	OutputLayers      uint32 `json:"output_layers"`
	MaterializedBytes uint64 `json:"materialized_bytes"`
	// TotalUs measures preparation/materialization, excluding journal adoption and backend switching.
	TotalUs uint64 `json:"total_us"`
}

// DiskCompactionResult reports physical counts and measured durations in microseconds.
// MaterializedBytes is work performed, not an estimate of reclaimed disk space.
// TotalUs covers the whole operation, including shared journal/backend adoption.
type DiskCompactionResult struct {
	DryRun            bool                       `json:"dry_run"`
	InputLayers       uint32                     `json:"input_layers"`
	SelectedLayers    uint32                     `json:"selected_layers"`
	OutputLayers      uint32                     `json:"output_layers"`
	MaterializedBytes uint64                     `json:"materialized_bytes"`
	TotalUs           uint64                     `json:"total_us"`
	PauseUs           uint64                     `json:"pause_us"`
	Disks             []DiskCompactionDiskResult `json:"disks"`
}

// Compact merges selected sealed prefixes without rewriting existing snapshots.
// By default it covers the root and all sandbox-owned data disks, never named/external disks or directories.
func (s *Sandbox) Compact(ctx context.Context, opts DiskCompactionOptions) (*DiskCompactionResult, error) {
	data, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	out, err := s.inner.Compact(ctx, string(data))
	return parseCompaction(out, err)
}

// Compact performs explicit maintenance on a running or stopped sandbox.
func (h *SandboxHandle) Compact(ctx context.Context, opts DiskCompactionOptions) (*DiskCompactionResult, error) {
	// A metadata handle must not redirect a cloud sandbox's name into local storage.
	if h.backendKind != BackendLocal {
		return nil, &Error{Kind: ErrUnsupportedOperation, Message: "disk compaction requires a local sandbox handle"}
	}
	data, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	out, err := ffi.CompactSandbox(ctx, 0, h.name, string(data))
	return parseCompaction(out, err)
}

func parseCompaction(out string, err error) (*DiskCompactionResult, error) {
	if err != nil {
		return nil, wrapFFI(err)
	}
	var result DiskCompactionResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

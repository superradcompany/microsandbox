package microsandbox

import (
	"context"
	"encoding/json"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// DiskCompactionOptions selects explicit maintenance, never persisted desired configuration.
type DiskCompactionOptions struct {
	// Layers counts the oldest physical layers including the base, excluding the writable head.
	// Nil selects all sealed layers; an explicit count must be at least two.
	Layers *uint32 `json:"layers,omitempty"`
	DryRun bool    `json:"dry_run,omitempty"`
}

// DiskCompactionResult reports physical counts and measured durations in microseconds.
// MaterializedBytes is work performed, not an estimate of reclaimed disk space.
type DiskCompactionResult struct {
	DryRun            bool   `json:"dry_run"`
	InputLayers       uint32 `json:"input_layers"`
	SelectedLayers    uint32 `json:"selected_layers"`
	OutputLayers      uint32 `json:"output_layers"`
	MaterializedBytes uint64 `json:"materialized_bytes"`
	TotalUs           uint64 `json:"total_us"`
	PauseUs           uint64 `json:"pause_us"`
}

// Compact merges the selected sealed prefix without rewriting existing snapshots.
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

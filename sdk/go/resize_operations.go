package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ResizeOutcome distinguishes operation ownership from resource convergence.
type ResizeOutcome string

const (
	ResizePending    ResizeOutcome = "pending"
	ResizeApplied    ResizeOutcome = "applied"
	ResizeSuperseded ResizeOutcome = "superseded"
)

// ResizeObservation describes the availability of authoritative guest evidence.
type ResizeObservation string

const (
	ResizeObservationAvailable   ResizeObservation = "available"
	ResizeObservationUnsupported ResizeObservation = "unsupported"
	ResizeObservationPaused      ResizeObservation = "paused"
	ResizeObservationUnavailable ResizeObservation = "unavailable"
)

// ResizeTarget is a CPU count or total memory allocation in MiB. Only the field
// selected by Resource ("cpus" or "memory") is used; targets retain integer precision.
type ResizeTarget struct {
	Resource string `json:"resource"`
	Online   uint32 `json:"online,omitempty"`
	TotalMiB uint64 `json:"total_mib,omitempty"`
}

// ResizeOperation identifies one accepted request in one runtime incarnation.
// Status is retained evidence, never authority to substitute a newer operation.
type ResizeOperation struct {
	ID              string               `json:"id"`
	RuntimeBootID   string               `json:"runtime_boot_id"`
	Generation      uint64               `json:"generation"`
	RequestedTarget ResizeTarget         `json:"requested_target"`
	AcceptedTarget  ResizeTarget         `json:"accepted_target"`
	Status          ResourceResizeStatus `json:"status"`
	Outcome         ResizeOutcome        `json:"outcome"`
	Observation     ResizeObservation    `json:"observation"`
}

// SandboxModificationResult keeps the ordinary plan and exact requests from this call.
type SandboxModificationResult struct {
	Plan SandboxModificationPlan `json:"plan"`
	// Nil means no tracked live request: dry run, a non-live change or an older runtime.
	ResizeOperations []ResizeOperation `json:"resize_operations"`
}

type resizeOperationRequest struct {
	Operation  string            `json:"operation"`
	Options    json.RawMessage   `json:"options,omitempty"`
	Operations []ResizeOperation `json:"operations,omitempty"`
	TimeoutMs  uint64            `json:"timeout_ms"`
}

// ModifyWithResizeTracking accepts Modify's options and returns exact live request identities.
// Ordinary Modify output is unchanged. Unsupported native libraries refuse before mutation;
// older runtimes retain supported mutations and return nil tracking. No mutation is retried.
func (s *Sandbox) ModifyWithResizeTracking(ctx context.Context, opts ModifyOptions) (*SandboxModificationResult, error) {
	request, err := trackedModifyRequest(opts)
	if err != nil {
		return nil, err
	}
	out, err := s.inner.ResizeOperations(ctx, request)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseModificationResult(out)
}

// ModifyWithResizeTracking preserves Modify's fresh-by-name planning and options.
// Stopped/next-start changes return no live identities and do not start the sandbox.
func (h *SandboxHandle) ModifyWithResizeTracking(ctx context.Context, opts ModifyOptions) (*SandboxModificationResult, error) {
	request, err := trackedModifyRequest(opts)
	if err != nil {
		return nil, err
	}
	out, err := ffi.ResizeOperationsSandboxByName(ctx, h.name, h.id, request)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseModificationResult(out)
}

// ResizeOperations reads the latest operation per resource without changing targets.
// Empty means no recorded request; unavailable observation never means completion.
func (s *Sandbox) ResizeOperations(ctx context.Context) ([]ResizeOperation, error) {
	out, err := s.inner.ResizeOperations(ctx, `{"operation":"read"}`)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseResizeOperations(out)
}

// ResizeOperations reads current records for this exact sandbox, refusing replacement.
func (h *SandboxHandle) ResizeOperations(ctx context.Context) ([]ResizeOperation, error) {
	out, err := ffi.ResizeOperationsSandboxByName(ctx, h.name, h.id, `{"operation":"read"}`)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseResizeOperations(out)
}

// WaitForResizeOperations waits on supplied identities, never selecting newer requests.
// Cancel ctx to end waiting without undoing the mutation. Runtime replacement, expired
// history, supersession and unsupported observation are errors, not successful completion.
func (s *Sandbox) WaitForResizeOperations(ctx context.Context, operations []ResizeOperation) ([]ResourceResizeStatus, error) {
	return s.waitForResizeOperations(ctx, operations, ffi.ResizeWaitUnbounded)
}

// WaitForResizeOperationsWithTimeout bounds waiting. Zero/negative checks once.
// ResizeTimeoutError preserves completed per-resource reads; timeout does not undo a resize.
func (s *Sandbox) WaitForResizeOperationsWithTimeout(ctx context.Context, operations []ResizeOperation, timeout time.Duration) ([]ResourceResizeStatus, error) {
	return s.waitForResizeOperations(ctx, operations, resizeTimeoutMillis(timeout))
}

// WaitForResizeOperations waits on supplied identities for this exact sandbox.
func (h *SandboxHandle) WaitForResizeOperations(ctx context.Context, operations []ResizeOperation) ([]ResourceResizeStatus, error) {
	return h.waitForResizeOperations(ctx, operations, ffi.ResizeWaitUnbounded)
}

// WaitForResizeOperationsWithTimeout includes identity lookup in the same deadline.
// Zero/negative checks once. Cancellation or timeout ends waiting only.
func (h *SandboxHandle) WaitForResizeOperationsWithTimeout(ctx context.Context, operations []ResizeOperation, timeout time.Duration) ([]ResourceResizeStatus, error) {
	return h.waitForResizeOperations(ctx, operations, resizeTimeoutMillis(timeout))
}

func (s *Sandbox) waitForResizeOperations(ctx context.Context, operations []ResizeOperation, timeoutMs uint64) ([]ResourceResizeStatus, error) {
	request, err := resizeWaitRequest(operations, timeoutMs)
	if err != nil {
		return nil, err
	}
	out, err := s.inner.ResizeOperations(ctx, request)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseResizeStatus(out)
}

func (h *SandboxHandle) waitForResizeOperations(ctx context.Context, operations []ResizeOperation, timeoutMs uint64) ([]ResourceResizeStatus, error) {
	request, err := resizeWaitRequest(operations, timeoutMs)
	if err != nil {
		return nil, err
	}
	out, err := ffi.ResizeOperationsSandboxByName(ctx, h.name, h.id, request)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseResizeStatus(out)
}

func trackedModifyRequest(opts ModifyOptions) (string, error) {
	if len(opts.Ports) > 0 || len(opts.PortsRemove) > 0 {
		if err := ffi.RequirePortModification(); err != nil {
			return "", wrapFFI(err)
		}
	}
	options, err := buildModifyRequestJSON(opts)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(resizeOperationRequest{Operation: "modify", Options: json.RawMessage(options)})
	return string(raw), err
}

func resizeWaitRequest(operations []ResizeOperation, timeoutMs uint64) (string, error) {
	if len(operations) == 0 || len(operations) > 2 {
		return "", fmt.Errorf("expected one or two resize operations")
	}
	raw, err := json.Marshal(resizeOperationRequest{Operation: "wait", Operations: operations, TimeoutMs: timeoutMs})
	return string(raw), err
}

func parseModificationResult(raw string) (*SandboxModificationResult, error) {
	var result SandboxModificationResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("parse tracked modification: %w", err)
	}
	return &result, nil
}

func parseResizeOperations(raw string) ([]ResizeOperation, error) {
	var operations []ResizeOperation
	if err := json.Unmarshal([]byte(raw), &operations); err != nil {
		return nil, fmt.Errorf("parse resize operations: %w", err)
	}
	return operations, nil
}

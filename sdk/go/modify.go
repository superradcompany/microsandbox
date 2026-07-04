package microsandbox

// Sandbox modification.
//
// Modify funnels through the Rust core's canonical patch/plan contract: the
// options below serialize into a SandboxModificationPatch, the core plans or
// applies it, and the returned plan JSON decodes into SandboxModificationPlan.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ModificationPolicy selects how a modification is planned or applied.
type ModificationPolicy string

const (
	// ModificationPolicyNoRestart applies only changes that can complete
	// without restarting the running sandbox. This is the default.
	ModificationPolicyNoRestart ModificationPolicy = "no_restart"

	// ModificationPolicyNextStart persists the desired config for the next
	// start and leaves any running VM unchanged.
	ModificationPolicyNextStart ModificationPolicy = "next_start"

	// ModificationPolicyRestart persists the patch and restarts the sandbox
	// if restart-required changes are present.
	ModificationPolicyRestart ModificationPolicy = "restart"
)

// ModifyOptions describes a requested sandbox modification. Zero-valued
// fields are left unchanged (0 is not a valid CPU or memory size).
type ModifyOptions struct {
	// CPUs sets the desired effective vCPU count.
	CPUs uint8

	// MaxCPUs sets the desired boot-time maximum possible vCPU count.
	MaxCPUs uint8

	// MemoryMiB sets the desired effective guest memory in MiB.
	MemoryMiB uint32

	// MaxMemoryMiB sets the desired boot-time maximum hotpluggable memory in MiB.
	MaxMemoryMiB uint32

	// Env sets environment variables for future execs.
	Env map[string]string

	// EnvRemove removes environment variable keys.
	EnvRemove []string

	// Labels sets sandbox labels.
	Labels map[string]string

	// LabelsRemove removes label keys.
	LabelsRemove []string

	// Workdir sets the working directory for future execs.
	Workdir string

	// Policy selects the apply policy. Defaults to ModificationPolicyNoRestart.
	Policy ModificationPolicy

	// DryRun computes the plan without applying anything.
	DryRun bool
}

// SandboxModificationPlan is the dry-run or apply plan returned by Modify.
type SandboxModificationPlan struct {
	// Sandbox being modified.
	Sandbox string `json:"sandbox"`

	// Status used for classification ("running", "stopped", ...).
	Status string `json:"status"`

	// Applied reports whether the changes were applied.
	Applied bool `json:"applied"`

	// Policy used to produce the plan.
	Policy ModificationPolicy `json:"policy"`

	// Changes planned by the core.
	Changes []PlannedChange `json:"changes"`

	// Conflicts that must be resolved before the patch can apply.
	Conflicts []ModificationConflict `json:"conflicts"`

	// Warnings about the patch or current runtime capabilities.
	Warnings []ModificationWarning `json:"warnings"`

	// ResizeStatus reports live resource resize outcomes after apply.
	ResizeStatus []ResourceResizeStatus `json:"resize_status,omitempty"`
}

// PlannedChange is one planned modification entry. Kind is "config" or
// "secret"; secret entries carry Name/BeforeRef/AfterRef/AllowHosts while
// config entries carry Before/After.
type PlannedChange struct {
	Kind        string   `json:"kind"`
	Field       string   `json:"field"`
	Name        string   `json:"name,omitempty"`
	Change      string   `json:"change"`
	Before      *string  `json:"before,omitempty"`
	After       *string  `json:"after,omitempty"`
	BeforeRef   *string  `json:"before_ref,omitempty"`
	AfterRef    *string  `json:"after_ref,omitempty"`
	Disposition string   `json:"disposition"`
	AllowHosts  []string `json:"allow_hosts,omitempty"`
	Reason      *string  `json:"reason,omitempty"`
}

// ModificationConflict blocks applying a modification.
type ModificationConflict struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ModificationWarning is a non-fatal warning emitted while planning.
type ModificationWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ResourceResizeStatus reports runtime convergence for a live resize.
type ResourceResizeStatus struct {
	Resource  string `json:"resource"`
	Requested string `json:"requested"`
	Actual    string `json:"actual"`
	Enforced  string `json:"enforced"`
	State     string `json:"state"`
}

// Modify plans or applies a sandbox modification on this live sandbox.
// With DryRun the plan is computed without applying anything.
func (s *Sandbox) Modify(ctx context.Context, opts ModifyOptions) (*SandboxModificationPlan, error) {
	payload, err := buildModifyRequestJSON(opts)
	if err != nil {
		return nil, err
	}
	out, err := s.inner.Modify(ctx, payload)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseModificationPlan(out)
}

// Modify plans or applies a sandbox modification by name. It does not start
// stopped sandboxes; next-start changes persist for the next boot.
func (h *SandboxHandle) Modify(ctx context.Context, opts ModifyOptions) (*SandboxModificationPlan, error) {
	payload, err := buildModifyRequestJSON(opts)
	if err != nil {
		return nil, err
	}
	out, err := ffi.ModifySandboxByName(ctx, h.name, payload)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseModificationPlan(out)
}

// modifyEnvVar mirrors the core EnvVar serde shape.
type modifyEnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// modifyPatch mirrors the core SandboxModificationPatch serde shape.
type modifyPatch struct {
	CPUs         *uint8         `json:"cpus,omitempty"`
	MaxCPUs      *uint8         `json:"max_cpus,omitempty"`
	MemoryMiB    *uint32        `json:"memory_mib,omitempty"`
	MaxMemoryMiB *uint32        `json:"max_memory_mib,omitempty"`
	Env          []modifyEnvVar `json:"env,omitempty"`
	EnvRemove    []string       `json:"env_remove,omitempty"`
	Labels       [][2]string    `json:"labels,omitempty"`
	LabelsRemove []string       `json:"labels_remove,omitempty"`
	Workdir      *string        `json:"workdir,omitempty"`
}

type modifyRequest struct {
	Patch  modifyPatch `json:"patch"`
	Policy string      `json:"policy,omitempty"`
	DryRun bool        `json:"dry_run,omitempty"`
}

// buildModifyRequestJSON serializes ModifyOptions into the FFI wire shape.
// Map entries are emitted in sorted key order so identical options always
// produce identical requests (and plan ordering).
func buildModifyRequestJSON(opts ModifyOptions) (string, error) {
	patch := modifyPatch{
		EnvRemove:    opts.EnvRemove,
		LabelsRemove: opts.LabelsRemove,
	}
	if opts.CPUs > 0 {
		patch.CPUs = &opts.CPUs
	}
	if opts.MaxCPUs > 0 {
		patch.MaxCPUs = &opts.MaxCPUs
	}
	if opts.MemoryMiB > 0 {
		patch.MemoryMiB = &opts.MemoryMiB
	}
	if opts.MaxMemoryMiB > 0 {
		patch.MaxMemoryMiB = &opts.MaxMemoryMiB
	}
	for _, key := range sortedKeys(opts.Env) {
		patch.Env = append(patch.Env, modifyEnvVar{Key: key, Value: opts.Env[key]})
	}
	for _, key := range sortedKeys(opts.Labels) {
		patch.Labels = append(patch.Labels, [2]string{key, opts.Labels[key]})
	}
	if opts.Workdir != "" {
		patch.Workdir = &opts.Workdir
	}

	raw, err := json.Marshal(modifyRequest{
		Patch:  patch,
		Policy: string(opts.Policy),
		DryRun: opts.DryRun,
	})
	if err != nil {
		return "", fmt.Errorf("marshal modify request: %w", err)
	}
	return string(raw), nil
}

func parseModificationPlan(raw string) (*SandboxModificationPlan, error) {
	var plan SandboxModificationPlan
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return nil, fmt.Errorf("parse modification plan: %w", err)
	}
	return &plan, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// SnapshotGroup is a mutable history over immutable checkpoints. Its receiver
// retains the backend that opened it; clearing head does not erase its members.
type SnapshotGroup = Snapshot

// Snapshot is a checkpoint history belonging to one provider.
type Snapshot struct {
	object *ffi.SnapshotObject
	name   string
}

// SnapshotGroupVerifyReport covers the membership pinned when verification began.
// State is complete, incomplete, invalid, or empty (zero checkpoints checked).
type SnapshotGroupVerifyReport struct {
	Group         string                   `json:"group"`
	State         string                   `json:"state"`
	Checkpoints   []CheckpointVerification `json:"checkpoints"`
	PayloadHashes uint64                   `json:"payload_hashes"`
}

// CheckpointVerification preserves existing artifact evidence and every observed finding.
type CheckpointVerification struct {
	ID       *string                       `json:"id"`
	Path     string                        `json:"path"`
	State    string                        `json:"state"`
	Report   *SnapshotVerifyReport         `json:"report"`
	Findings []SnapshotVerificationFinding `json:"findings"`
}

// SnapshotVerificationFinding identifies missing, invalid, unavailable, changed, unsupported,
// or not_recorded evidence without requiring callers to parse the diagnostic.
type SnapshotVerificationFinding struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Verify checks every member. Failures return a SnapshotVerificationError containing the report.
func (g *SnapshotGroup) Verify(ctx context.Context) (*SnapshotGroupVerifyReport, error) {
	var report SnapshotGroupVerifyReport
	if err := snapshotObjectRequest(ctx, g.object, map[string]any{"op": "verify"}, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// SnapshotRemoveResult records all members removed by one committed history removal.
type SnapshotRemoveResult struct {
	Group      string              `json:"group"`
	Removed    []string            `json:"removed"`
	HeadUpdate *SnapshotHeadUpdate `json:"head_update"`
	Warnings   []string            `json:"warnings"`
}

// Remove removes the entire history, refusing active readers and external dependents.
func (g *SnapshotGroup) Remove(ctx context.Context) (*SnapshotRemoveResult, error) {
	var result SnapshotRemoveResult
	if err := snapshotObjectRequest(ctx, g.object, map[string]any{"op": "remove_group"}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SnapshotSourceStatus describes association availability, not future capture readiness.
type SnapshotSourceStatus string

const (
	SnapshotSourceAvailable        SnapshotSourceStatus = "available"
	SnapshotSourceMissingSandbox   SnapshotSourceStatus = "missing_sandbox"
	SnapshotSourceDifferentCatalog SnapshotSourceStatus = "different_catalog"
)

// SnapshotSourceBinding identifies the original instance independently of its name.
type SnapshotSourceBinding struct {
	DatabaseUUID string               `json:"database_uuid"`
	SandboxID    int32                `json:"sandbox_id"`
	RecordedName string               `json:"recorded_name"`
	CurrentName  *string              `json:"current_name"`
	Status       SnapshotSourceStatus `json:"status"`
}

// SnapshotGroupInfo is one protected metadata observation. Source is nil when unbound.
type SnapshotGroupInfo struct {
	Name            string                 `json:"name"`
	Path            string                 `json:"path"`
	Head            *string                `json:"head"`
	CheckpointCount uint64                 `json:"checkpoint_count"`
	Source          *SnapshotSourceBinding `json:"source"`
}

// Inspect observes history metadata and its saved source without changing selection.
func (g *SnapshotGroup) Inspect(ctx context.Context) (*SnapshotGroupInfo, error) {
	var info SnapshotGroupInfo
	if err := snapshotObjectRequest(ctx, g.object, map[string]any{"op": "inspect_group"}, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SnapshotCreateResult owns the initial checkpoint, even if head changes later.
type SnapshotCreateResult struct {
	Snapshot   *SnapshotGroup
	Checkpoint *Checkpoint
	HeadUpdate *SnapshotHeadUpdate
}

// CheckpointCaptureResult reports this capture's publication, never a later head lookup.
type CheckpointCaptureResult struct {
	Checkpoint *Checkpoint
	HeadUpdate *SnapshotHeadUpdate
}

// SnapshotImportOptions configures a canonical import; the destination group is positional.
// Legacy Checkpoint.LoadWithOptions/LoadMany retain SnapshotLoadOptions and its Group field.
type SnapshotImportOptions struct {
	// Parent directory containing snapshot groups; empty selects the default.
	Dest string
	// External snapshot or archive for dependencies absent from the batch/group.
	Base string
	// Select the unique imported tip even when it is not a fast-forward.
	SetHead bool
	// Maximum logical bytes imported; nil means unlimited.
	MaximumDiskBytes *uint64 `json:"maximum_disk_bytes,omitempty"`
}

// SnapshotImportResult contains only facts from this committed import attempt.
type SnapshotImportResult struct {
	OperationID string
	Snapshot    *SnapshotGroup
	Checkpoints []*Checkpoint
	Added       []string
	Reused      []string
	HeadUpdate  *SnapshotHeadUpdate
	Warnings    []string
}

// SnapshotCaptureConfig controls capture only; the receiver fixes the source.
type SnapshotCaptureConfig struct {
	Name            string            `json:"name,omitempty"`
	Destination     string            `json:"destination,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Full            bool              `json:"full"`
	RecordIntegrity bool              `json:"record_integrity"`
	GuestFlush      GuestFlush        `json:"guest_flush,omitempty"`
}

type SnapshotCaptureOption func(*SnapshotCaptureConfig)

func WithSnapshotCaptureConfig(config SnapshotCaptureConfig) SnapshotCaptureOption {
	return func(options *SnapshotCaptureConfig) { *options = config }
}

// Snapshots selects histories in a single provider context.
type Snapshots struct{ selected Context }

func SnapshotCtx(selected Context) *Snapshots { return &Snapshots{selected: selected} }
func (s *Snapshots) Context() Context         { return s.selected }
func (s *Snapshots) root() (*ffi.SnapshotObject, error) {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return nil, err
	}
	return destination.SnapshotRoot(), nil
}

func checkpointFromRegistration(owner *ffi.SnapshotObject, raw json.RawMessage) (*Checkpoint, error) {
	inner, err := owner.Resource(raw)
	if err != nil {
		return nil, err
	}
	return snapshotFromResource(inner)
}
func checkpointsFromRegistrations(owner *ffi.SnapshotObject, items []json.RawMessage) ([]*Checkpoint, error) {
	checkpoints := make([]*Checkpoint, 0, len(items))
	for _, item := range items {
		member, err := checkpointFromRegistration(owner, item)
		if err != nil {
			return nil, err
		}
		checkpoints = append(checkpoints, member)
	}
	return checkpoints, nil
}

type snapshotGroupWire struct {
	ObjectHandle uint64 `json:"object_handle"`
	Name         string `json:"name"`
}

type snapshotCaptureWire struct {
	Snapshot   *snapshotGroupWire      `json:"snapshot"`
	Checkpoint json.RawMessage         `json:"checkpoint"`
	HeadUpdate *ffi.SnapshotHeadUpdate `json:"head_update"`
}

func snapshotGroupFromWire(owner *ffi.SnapshotObject, group *snapshotGroupWire) (*SnapshotGroup, error) {
	if group == nil || group.ObjectHandle == 0 {
		return nil, fmt.Errorf("native SDK returned no snapshot group receiver")
	}
	return &SnapshotGroup{object: owner.Child(group.ObjectHandle), name: group.Name}, nil
}

func snapshotObjectRequest(ctx context.Context, object *ffi.SnapshotObject, request any, out any) error {
	var data []byte
	var err error
	if object == nil {
		data, err = ffi.SnapshotObjectCall(ctx, 0, request)
	} else {
		data, err = object.Call(ctx, request)
	}
	if err != nil {
		return wrapFFI(err)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse snapshot operation: %w", err)
	}
	return nil
}

// Load atomically imports files into a named group, with optional dependency/head policy.
func (s *Snapshots) Load(ctx context.Context, group string, files []string, options ...SnapshotImportOptions) (*SnapshotImportResult, error) {
	if len(options) > 1 {
		return nil, fmt.Errorf("snapshot load accepts at most one options value")
	}
	owner, err := s.root()
	if err != nil {
		return nil, err
	}
	var opts SnapshotImportOptions
	if len(options) == 1 {
		opts = options[0]
	}
	// Native dispatch can run after another goroutine changes the process cwd.
	// The selected provider owns remote references, including relative strings.
	var directory string
	if s.selected.Kind() == ContextLocal {
		files, opts, directory, err = prepareGroupImportPaths(files, opts)
		if err != nil {
			return nil, err
		}
	}
	var wire struct {
		OperationID string                  `json:"operation_id"`
		Snapshot    *snapshotGroupWire      `json:"snapshot"`
		Checkpoints []json.RawMessage       `json:"checkpoints"`
		Added       []string                `json:"added"`
		Reused      []string                `json:"reused"`
		HeadUpdate  *ffi.SnapshotHeadUpdate `json:"head_update"`
		Warnings    []string                `json:"warnings"`
	}
	if err := snapshotObjectRequest(ctx, owner, map[string]any{"op": "load", "name": group, "files": files,
		"options": ffi.SnapshotLoadOptions{CallerDirectory: directory, Dest: opts.Dest, Base: opts.Base, SetHead: opts.SetHead, MaximumDiskBytes: opts.MaximumDiskBytes}}, &wire); err != nil {
		return nil, err
	}
	history, err := snapshotGroupFromWire(owner, wire.Snapshot)
	if err != nil {
		return nil, err
	}
	checkpoints, err := checkpointsFromRegistrations(owner, wire.Checkpoints)
	if err != nil {
		return nil, err
	}
	return &SnapshotImportResult{OperationID: wire.OperationID, Snapshot: history, Checkpoints: checkpoints,
		Added: wire.Added, Reused: wire.Reused, HeadUpdate: snapshotHeadUpdateFromInfo(wire.HeadUpdate), Warnings: wire.Warnings}, nil
}

// An ordinary relative input keeps its spelling until Rust resolves it against
// this directory. On Unix, cleaning "link/../file" could change the selected file.
func prepareGroupImportPaths(files []string, opts SnapshotImportOptions) ([]string, SnapshotImportOptions, string, error) {
	relative := func(path string) bool { return path != "" && !filepath.IsAbs(path) }
	if !relative(opts.Dest) && !relative(opts.Base) && !slices.ContainsFunc(files, relative) {
		return files, opts, "", nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, opts, "", err
	}
	if filepath.Separator == '\\' {
		// Windows keeps a working directory per drive. Resolve drive-relative
		// inputs such as D:base.msb on the caller before native dispatch.
		paths := slices.Clone(files)
		resolveDrive := func(path string) (string, error) {
			if relative(path) && filepath.VolumeName(path) != "" {
				return filepath.Abs(path)
			}
			return path, nil
		}
		for i := range paths {
			if paths[i], err = resolveDrive(paths[i]); err != nil {
				return nil, opts, "", err
			}
		}
		if opts.Dest, err = resolveDrive(opts.Dest); err != nil {
			return nil, opts, "", err
		}
		if opts.Base, err = resolveDrive(opts.Base); err != nil {
			return nil, opts, "", err
		}
		files = paths
	}
	return files, opts, cwd, nil
}

// Anchor before a native future can run on another goroutine. On Unix a symlink
// followed by .. must be resolved by the filesystem, so preserve its spelling.
func anchorSnapshotDirectory(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) {
		return path, nil
	}
	if filepath.Separator == '\\' {
		return filepath.Abs(path)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(cwd, string(os.PathSeparator)) + string(os.PathSeparator) + path, nil
}

// Open reopens an explicit local history directory without default-store lookup.
func (s *Snapshots) Open(ctx context.Context, path string) (*SnapshotGroup, error) {
	owner, err := s.root()
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("snapshot group path cannot be empty")
	}
	path, err = anchorSnapshotDirectory(path)
	if err != nil {
		return nil, err
	}
	var wire snapshotGroupWire
	data, err := owner.Call(ctx, map[string]any{"op": "open_group", "directory": path})
	if err != nil {
		return nil, wrapFFI(err)
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("parse snapshot group: %w", err)
	}
	return snapshotGroupFromWire(owner, &wire)
}

func (s *Snapshots) Get(ctx context.Context, name string) (*SnapshotGroup, error) {
	owner, err := s.root()
	if err != nil {
		return nil, err
	}
	var wire snapshotGroupWire
	if err := snapshotObjectRequest(ctx, owner, map[string]any{"op": "get", "name": name}, &wire); err != nil {
		return nil, err
	}
	return snapshotGroupFromWire(owner, &wire)
}

func (s *Snapshots) List(ctx context.Context) ([]*SnapshotGroup, error) {
	owner, err := s.root()
	if err != nil {
		return nil, err
	}
	var wire []*snapshotGroupWire
	if err := snapshotObjectRequest(ctx, owner, map[string]any{"op": "list"}, &wire); err != nil {
		return nil, err
	}
	groups := make([]*SnapshotGroup, 0, len(wire))
	for _, item := range wire {
		group, err := snapshotGroupFromWire(owner, item)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (group *SnapshotGroup) Name() string { return group.name }

// Head returns nil for an explicitly headless history.
func (group *SnapshotGroup) Head(ctx context.Context) (*Checkpoint, error) {
	var info json.RawMessage
	if err := snapshotObjectRequest(ctx, group.object, map[string]any{"op": "head"}, &info); err != nil {
		return nil, err
	}
	if string(info) == "null" {
		return nil, nil
	}
	return checkpointFromRegistration(group.object, info)
}

func (group *SnapshotGroup) GetCheckpoint(ctx context.Context, name string) (*Checkpoint, error) {
	var info json.RawMessage
	if err := snapshotObjectRequest(ctx, group.object, map[string]any{"op": "member", "name": name}, &info); err != nil {
		return nil, err
	}
	return checkpointFromRegistration(group.object, info)
}

func (group *SnapshotGroup) Checkpoints(ctx context.Context) ([]*Checkpoint, error) {
	var infos []json.RawMessage
	if err := snapshotObjectRequest(ctx, group.object, map[string]any{"op": "members"}, &infos); err != nil {
		return nil, err
	}
	return checkpointsFromRegistrations(group.object, infos)
}

func (group *SnapshotGroup) SetHead(ctx context.Context, member string) (*SnapshotHeadUpdate, error) {
	var update ffi.SnapshotHeadUpdate
	if err := snapshotObjectRequest(ctx, group.object, map[string]any{"op": "set_head", "name": member}, &update); err != nil {
		return nil, err
	}
	return snapshotHeadUpdateFromInfo(&update), nil
}

func (group *SnapshotGroup) ClearHead(ctx context.Context) (*SnapshotHeadUpdate, error) {
	var update ffi.SnapshotHeadUpdate
	if err := snapshotObjectRequest(ctx, group.object, map[string]any{"op": "clear_head"}, &update); err != nil {
		return nil, err
	}
	return snapshotHeadUpdateFromInfo(&update), nil
}

func (group *SnapshotGroup) Checkpoint(ctx context.Context, opts ...SnapshotCaptureOption) (*CheckpointCaptureResult, error) {
	options := SnapshotCaptureConfig{}
	for _, configure := range opts {
		configure(&options)
	}
	var result snapshotCaptureWire
	if err := snapshotObjectRequest(ctx, group.object, map[string]any{"op": "capture", "options": options}, &result); err != nil {
		return nil, err
	}
	if result.Checkpoint == nil {
		return nil, fmt.Errorf("native SDK returned no captured checkpoint")
	}
	member, err := checkpointFromRegistration(group.object, result.Checkpoint)
	if err != nil {
		return nil, err
	}
	return &CheckpointCaptureResult{Checkpoint: member, HeadUpdate: snapshotHeadUpdateFromInfo(result.HeadUpdate)}, nil
}

// Snapshot creates a new group; an existing group is an error, never an append.
func (sandbox *Sandbox) Snapshot(ctx context.Context, name string, opts ...SnapshotCaptureOption) (*SnapshotCreateResult, error) {
	options := SnapshotCaptureConfig{}
	for _, configure := range opts {
		configure(&options)
	}
	if sandbox.ContextKind() == ContextLocal {
		directory, err := anchorSnapshotDirectory(options.Destination)
		if err != nil {
			return nil, err
		}
		options.Destination = directory
	}
	owner := sandbox.inner.SnapshotRoot()
	var result snapshotCaptureWire
	if err := snapshotObjectRequest(ctx, owner, map[string]any{"op": "create", "sandbox": sandbox.inner.Handle(), "name": name, "options": options}, &result); err != nil {
		return nil, err
	}
	group, err := snapshotGroupFromWire(owner, result.Snapshot)
	if err != nil {
		return nil, err
	}
	if result.Checkpoint == nil {
		return nil, fmt.Errorf("native SDK returned no initial checkpoint")
	}
	member, err := checkpointFromRegistration(owner, result.Checkpoint)
	if err != nil {
		return nil, err
	}
	return &SnapshotCreateResult{Snapshot: group, Checkpoint: member, HeadUpdate: snapshotHeadUpdateFromInfo(result.HeadUpdate)}, nil
}

// Save exports this exact checkpoint, using the retained receiver when available.
func (checkpoint *Checkpoint) Save(ctx context.Context, path string, opts ...SnapshotSaveOptions) error {
	// Accept one explicit options value or defaults; silently choosing one of several
	// values could discard a requested compatibility target or dependency policy.
	if len(opts) > 1 {
		return &Error{Kind: ErrInvalidConfig, Message: "checkpoint save accepts at most one options value"}
	}
	var options SnapshotSaveOptions
	if len(opts) == 1 {
		options = opts[0]
	}
	return checkpoint.SaveTo(ctx, path, options)
}

func snapshotSaveOptionsWire(options SnapshotSaveOptions) map[string]any {
	result := map[string]any{"with_parents": options.WithParents, "with_image": options.WithImage, "plain_tar": options.PlainTar}
	if options.Compatibility != "" {
		result["compatibility"] = options.Compatibility
	}
	if options.Since != "" {
		result["since"] = options.Since
	}
	if options.LastLayers != nil {
		result["last_layers"] = *options.LastLayers
	}
	return result
}

func spawnSnapshotReceiver(ctx context.Context, object *ffi.SnapshotObject, name string, progress uint64, opts []RestoreOption) (*ffi.Sandbox, error) {
	if object == nil {
		return nil, &ffi.Error{Kind: ffi.KindUnsupportedOperation, Message: "checkpoint spawn requires a retained receiver from an updated native library; reopen it with Checkpoint.Open if supported"}
	}
	config := RestoreConfig{}
	for _, configure := range opts {
		configure(&config)
	}
	if err := validateRestoreConfig(config); err != nil {
		return nil, err
	}
	// The empty reference is a placeholder only; the native receiver replaces it
	// with its exact checkpoint and original backend before preparation.
	options := buildFFIRestoreOptions("", config)
	options.CreationProgress = progress
	return object.Spawn(ctx, name, options)
}

func (group *SnapshotGroup) SpawnSandbox(ctx context.Context, name string, opts ...RestoreOption) (*Sandbox, error) {
	inner, err := spawnSnapshotReceiver(ctx, group.object, name, 0, opts)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

func (checkpoint *Checkpoint) SpawnSandbox(ctx context.Context, name string, opts ...RestoreOption) (*Sandbox, error) {
	inner, err := spawnSnapshotReceiver(ctx, checkpoint.inner.SnapshotReceiver(), name, 0, opts)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Sandbox{inner: inner}, nil
}

func (group *SnapshotGroup) SpawnSandboxWithProgress(ctx context.Context, name string, opts ...RestoreOption) (<-chan CreationProgress, <-chan CreationResult) {
	return sandboxWithProgress(ctx, group.object.Library(), func(progress uint64) (*ffi.Sandbox, error) {
		return spawnSnapshotReceiver(ctx, group.object, name, progress, opts)
	})
}

func (checkpoint *Checkpoint) SpawnSandboxWithProgress(ctx context.Context, name string, opts ...RestoreOption) (<-chan CreationProgress, <-chan CreationResult) {
	return sandboxWithProgress(ctx, checkpoint.inner.SnapshotReceiver().Library(), func(progress uint64) (*ffi.Sandbox, error) {
		return spawnSnapshotReceiver(ctx, checkpoint.inner.SnapshotReceiver(), name, progress, opts)
	})
}

// CheckpointRemoveResult records the identity and head decision of one removal.
// HeadUpdate is nil only for a standalone artifact outside a group.
type CheckpointRemoveResult struct {
	ID         string              `json:"id"`
	HeadUpdate *SnapshotHeadUpdate `json:"head_update"`
	Warnings   []string            `json:"warnings"`
}

// CheckpointRemoveOptions controls dependent-checkpoint handling, never reader protection.
type CheckpointRemoveOptions struct{ Force bool }

// Remove deletes this exact retained checkpoint and returns its publication outcome.
func (s *Checkpoint) Remove(ctx context.Context, options ...CheckpointRemoveOptions) (*CheckpointRemoveResult, error) {
	if len(options) > 1 {
		return nil, fmt.Errorf("checkpoint removal accepts at most one options value")
	}
	if s.inner == nil {
		return nil, &Error{Kind: ErrUnsupportedOperation, Message: "exact checkpoint removal requires a retained receiver from an updated native library"}
	}
	force := len(options) == 1 && options[0].Force
	var result CheckpointRemoveResult
	if err := snapshotObjectRequest(ctx, s.inner.SnapshotReceiver(), map[string]any{"op": "remove", "force": force}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// SnapshotCreateOptions configures Snapshot.Create.
type SnapshotCreateOptions struct {
	// Snapshot member name; generated when empty by the local backend.
	Name string
	// Group to install the member in; defaults to the source sandbox's name.
	Group string
	// Source sandbox to snapshot. Disk capture preserves running/paused state. Required.
	FromSandbox string
	// Local group parent or cloud host-volume directory; empty selects backend-managed storage.
	DestDir         string
	Labels          map[string]string
	Force           bool
	RecordIntegrity bool
	// Full includes memory and execution state from a running or paused source.
	// False captures disk state from running, paused, stopped, or crashed sources.
	Full bool
	// GuestFlush defaults to Auto: flush live disk captures, not full captures.
	GuestFlush GuestFlush
}

// SnapshotSaveOptions configures Snapshot.Save and instance SaveTo methods.
type SnapshotSaveOptions struct {
	// Since omits disk layers and RAM objects supplied by a base snapshot or standalone archive.
	Since string
	// LastLayers includes the newest N sealed root-disk layers; owned disks remain complete.
	// Mutually exclusive with Since and WithParents.
	LastLayers  *uint32
	WithParents bool
	WithImage   bool
	PlainTar    bool
}

// SnapshotLoadOptions configures importing one or more archives into a snapshot group.
type SnapshotLoadOptions struct {
	// Maximum expanded payload bytes; nil leaves size unlimited.
	MaximumDiskBytes *uint64
	// Parent directory containing snapshot groups; empty selects the default.
	Dest string
	// External snapshot or standalone archive for dependencies absent from the batch/group.
	Base string
	// Destination group; generated when empty.
	Group string
	// Select the unique imported tip even when it is not a fast-forward.
	SetHead bool
}

// SnapshotHeadUpdate reports the result of reading or selecting a group head.
type SnapshotHeadUpdate struct {
	Group    string
	Previous *string
	Head     string
	Reason   string
	Changed  bool
}

// SnapshotArchiveOptions configures direct sandbox-to-archive capture.
type SnapshotArchiveOptions struct {
	SnapshotCreateOptions
	ArchivePath string
	PlainTar    bool
}

// SnapshotArchive identifies a directly captured archive. It does not
// represent an installed snapshot artifact or index row.
type SnapshotArchive struct {
	id               string
	descriptorDigest string
	path             string
}

func (a *SnapshotArchive) ID() string               { return a.id }
func (a *SnapshotArchive) DescriptorDigest() string { return a.descriptorDigest }
func (a *SnapshotArchive) Path() string             { return a.path }

// SnapshotCopyBuilder configures a new archive containing an existing
// snapshot's disk data and replacement metadata.
type SnapshotCopyBuilder struct {
	snapshot          *Snapshot
	outputArchivePath string
	labels            map[string]string
	recordIntegrity   bool
}

// Snapshot payload scope values, as reported by Snapshot.Scope
// and Snapshot.Scope.
const (
	SnapshotScopeDisk = "disk"
	SnapshotScopeFull = "full"
)

// SnapshotVerifyReport is returned by Snapshot.Verify.
type SnapshotVerifyReport struct {
	Digest     string
	Path       string
	Upper      SnapshotUpperVerifyStatus
	Checkpoint *SnapshotCheckpointVerifyStatus
}

// SnapshotCheckpointVerifyStatus identifies a fully verified checkpoint closure.
type SnapshotCheckpointVerifyStatus struct {
	Kind string
	Root string
}

type SnapshotUpperVerifyStatus struct {
	Kind      string
	Algorithm string
	Digest    string
}

// SnapshotState is the closed schema-1 state family. Exactly one of File or
// Checkpoint is populated according to Kind.
type SnapshotState struct {
	Kind       string
	File       *SnapshotFileState
	Checkpoint *SnapshotCheckpointState
}

type SnapshotFileState struct {
	Format       string
	Fstype       string
	UpperFile    string
	SizeBytes    uint64
	HasIntegrity bool
	Integrity    SnapshotIntegrity
}

type SnapshotCheckpointState struct {
	CheckpointID   string
	ManifestDigest string
}

type SnapshotIntegrity struct {
	Algorithm   string
	Digest      string
	Root        string
	LogicalSize uint64
	LeafSize    uint32
}

// Snapshot is one persistent resource returned by creation, lookup, listing and import.
// Artifact metadata is loaded only by the methods that need it.
type Snapshot struct {
	inner         *ffi.PersistentResource
	id            string
	name          *string
	group         *string
	reference     string
	referenceKind string
	path          *string
	digest        string
	headUpdate    *SnapshotHeadUpdate
}

func snapshotFromResource(inner *ffi.PersistentResource) (*Snapshot, error) {
	var info ffi.SnapshotHandleInfo
	if err := json.Unmarshal(inner.Observation, &info); err != nil {
		return nil, err
	}
	return &Snapshot{inner: inner, id: info.ID, name: cloneStringPtr(info.Name), group: cloneStringPtr(info.Group), reference: info.Reference, referenceKind: info.ReferenceKind, path: cloneStringPtr(info.Path), digest: info.Digest, headUpdate: snapshotHeadUpdateFromInfo(info.HeadUpdate)}, nil
}
func (s *Snapshot) ID() string                      { return s.id }
func (s *Snapshot) Name() *string                   { return cloneStringPtr(s.name) }
func (s *Snapshot) Group() *string                  { return cloneStringPtr(s.group) }
func (s *Snapshot) Reference() string               { return s.reference }
func (s *Snapshot) ReferenceKind() string           { return s.referenceKind }
func (s *Snapshot) Digest() string                  { return s.digest }
func (s *Snapshot) Context() Context                { return contextFromNative(s.inner.Context()) }
func (s *Snapshot) HeadUpdate() *SnapshotHeadUpdate { return cloneSnapshotHeadUpdate(s.headUpdate) }

// Path returns an error for destinations that do not expose a local artifact path.
func (s *Snapshot) Path() (string, error) {
	if s.path == nil {
		return "", &Error{Kind: ErrUnsupportedOperation, Message: "snapshot has no local artifact path"}
	}
	return *s.path, nil
}

// Manifest fetches and validates artifact metadata; lookup and list do not load it eagerly.
func (s *Snapshot) Manifest(ctx context.Context) (map[string]any, error) {
	var manifest map[string]any
	err := s.inner.Operation(ctx, "manifest", nil, &manifest)
	return manifest, wrapFFI(err)
}
func (s *Snapshot) metadata(ctx context.Context) (*ffi.SnapshotInfo, error) {
	var info ffi.SnapshotInfo
	if err := s.inner.Operation(ctx, "metadata", nil, &info); err != nil {
		return nil, wrapFFI(err)
	}
	return &info, nil
}
func (s *Snapshot) State(ctx context.Context) (SnapshotState, error) {
	info, err := s.metadata(ctx)
	if err != nil {
		return SnapshotState{}, err
	}
	return snapshotStateFromInfo(info), nil
}
func (s *Snapshot) Labels(ctx context.Context) (map[string]string, error) {
	info, err := s.metadata(ctx)
	if err != nil {
		return nil, err
	}
	return cloneMap(info.Labels), nil
}
func (s *Snapshot) Verify(ctx context.Context) (*SnapshotVerifyReport, error) {
	var report ffi.SnapshotVerifyReport
	if err := s.inner.Operation(ctx, "verify", nil, &report); err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotVerifyReportFromInfo(&report), nil
}
func (s *Snapshot) Destroy(ctx context.Context, force bool) error {
	return wrapFFI(s.inner.Operation(ctx, "destroy", map[string]any{"force": force}, nil))
}
func (s *Snapshot) SaveTo(ctx context.Context, path string, opts SnapshotSaveOptions) error {
	return wrapFFI(s.inner.Operation(ctx, "save", map[string]any{"path": path, "options": ffi.SnapshotSaveOptions{WithParents: opts.WithParents, WithImage: opts.WithImage, PlainTar: opts.PlainTar, Since: opts.Since, LastLayers: opts.LastLayers}}, nil))
}
func (s *Snapshot) CopyTo(path string) *SnapshotCopyBuilder {
	return &SnapshotCopyBuilder{snapshot: s, outputArchivePath: path, labels: map[string]string{}}
}
func (b *SnapshotCopyBuilder) Labels(labels map[string]string) *SnapshotCopyBuilder {
	b.labels = cloneMap(labels)
	return b
}
func (b *SnapshotCopyBuilder) RecordIntegrity(enabled bool) *SnapshotCopyBuilder {
	b.recordIntegrity = enabled
	return b
}
func (b *SnapshotCopyBuilder) Save(ctx context.Context) error {
	if b == nil || b.snapshot == nil {
		return &Error{Kind: ErrInvalidConfig, Message: "snapshot copy builder has no source"}
	}
	return wrapFFI(b.snapshot.inner.Operation(ctx, "copy", map[string]any{"path": b.outputArchivePath, "options": ffi.SnapshotCopyOptions{Labels: b.labels, RecordIntegrity: b.recordIntegrity}}, nil))
}

type Snapshots struct{ selected Context }

func SnapshotCtx(selected Context) *Snapshots { return &Snapshots{selected: selected} }
func (s *Snapshots) Context() Context         { return s.selected }
func (s *Snapshots) operation(ctx context.Context, operation, name string, args any) ([]*Snapshot, error) {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return nil, err
	}
	resources, err := destination.Resources(ctx, operation, name, args)
	if err != nil {
		return nil, wrapFFI(err)
	}
	snapshots := make([]*Snapshot, len(resources))
	for i, resource := range resources {
		snapshots[i], err = snapshotFromResource(resource)
		if err != nil {
			return nil, err
		}
	}
	return snapshots, nil
}
func (s *Snapshots) request(ctx context.Context, operation, name string, args, result any) error {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return err
	}
	return wrapFFI(destination.Request(ctx, operation, name, args, result))
}
func oneSnapshot(snapshots []*Snapshot, err error) (*Snapshot, error) {
	if err != nil {
		return nil, err
	}
	if len(snapshots) != 1 {
		return nil, fmt.Errorf("native lookup did not return one snapshot")
	}
	return snapshots[0], nil
}
func snapshotCreateOptions(opts SnapshotCreateOptions) ffi.SnapshotCreateOptions {
	return ffi.SnapshotCreateOptions{Name: opts.Name, Group: opts.Group, DestDir: opts.DestDir, Labels: opts.Labels, Force: opts.Force, RecordIntegrity: opts.RecordIntegrity, Full: opts.Full, GuestFlush: string(opts.GuestFlush)}
}
func (s *Snapshots) Create(ctx context.Context, opts SnapshotCreateOptions) (*Snapshot, error) {
	if opts.FromSandbox == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot create requires a source sandbox (FromSandbox)"}
	}
	return oneSnapshot(s.operation(ctx, "snapshot_create", opts.FromSandbox, snapshotCreateOptions(opts)))
}
func (s *Snapshots) CreateArchive(ctx context.Context, opts SnapshotArchiveOptions) (*SnapshotArchive, error) {
	if opts.FromSandbox == "" || opts.ArchivePath == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot archive create requires FromSandbox and ArchivePath"}
	}
	var result ffi.SnapshotArchiveInfo
	err := s.request(ctx, "snapshot_create_archive", opts.FromSandbox, map[string]any{"path": opts.ArchivePath, "plain_tar": opts.PlainTar, "options": snapshotCreateOptions(opts.SnapshotCreateOptions)}, &result)
	if err != nil {
		return nil, err
	}
	return &SnapshotArchive{id: result.ID, descriptorDigest: result.DescriptorDigest, path: result.Path}, nil
}
func (s *Snapshots) Get(ctx context.Context, name string) (*Snapshot, error) {
	return oneSnapshot(s.operation(ctx, "snapshot_get", name, nil))
}
func (s *Snapshots) Open(ctx context.Context, reference string) (*Snapshot, error) {
	return oneSnapshot(s.operation(ctx, "snapshot_open", reference, nil))
}
func (s *Snapshots) List(ctx context.Context) ([]*Snapshot, error) {
	return s.operation(ctx, "snapshot_list", "", nil)
}
func (s *Snapshots) ListDir(ctx context.Context, dir string) ([]*Snapshot, error) {
	return s.operation(ctx, "snapshot_list_dir", dir, nil)
}
func (s *Snapshots) Remove(ctx context.Context, reference string, force bool) error {
	_, err := s.operation(ctx, "snapshot_remove", reference, map[string]any{"force": force})
	return err
}
func (s *Snapshots) Reindex(ctx context.Context, dir string) (uint32, error) {
	var result struct {
		Count uint32 `json:"count"`
	}
	err := s.request(ctx, "snapshot_reindex", dir, nil, &result)
	return result.Count, err
}
func (s *Snapshots) Save(ctx context.Context, reference, path string, opts SnapshotSaveOptions) error {
	snapshot, err := s.Open(ctx, reference)
	if err != nil {
		return err
	}
	return snapshot.SaveTo(ctx, path, opts)
}
func (s *Snapshots) Load(ctx context.Context, archive, dest string) (*Snapshot, error) {
	return s.LoadWithOptions(ctx, archive, SnapshotLoadOptions{Dest: dest})
}
func (s *Snapshots) LoadWithBase(ctx context.Context, archive, dest, base string) (*Snapshot, error) {
	return s.LoadWithOptions(ctx, archive, SnapshotLoadOptions{Dest: dest, Base: base})
}
func (s *Snapshots) LoadWithOptions(ctx context.Context, archive string, opts SnapshotLoadOptions) (*Snapshot, error) {
	return oneSnapshot(s.LoadMany(ctx, []string{archive}, opts))
}
func (s *Snapshots) LoadMany(ctx context.Context, archives []string, opts SnapshotLoadOptions) ([]*Snapshot, error) {
	operation := "snapshot_load"
	if opts.MaximumDiskBytes != nil {
		operation = "snapshot_load_with_size_limit"
	}
	return s.operation(ctx, operation, "", map[string]any{"archives": archives, "options": ffi.SnapshotLoadOptions{Dest: opts.Dest, Base: opts.Base, Group: opts.Group, SetHead: opts.SetHead, MaximumDiskBytes: opts.MaximumDiskBytes}})
}
func (s *Snapshots) GroupHead(ctx context.Context, selector string) (*SnapshotHeadUpdate, error) {
	var result ffi.SnapshotHeadUpdate
	if err := s.request(ctx, "snapshot_group_head", selector, nil, &result); err != nil {
		return nil, err
	}
	return snapshotHeadUpdateFromInfo(&result), nil
}

func CreateSnapshot(ctx context.Context, opts SnapshotCreateOptions) (*Snapshot, error) {
	if opts.FromSandbox == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot create requires a source sandbox (FromSandbox)"}
	}
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().Create(ctx, opts)
}
func CreateSnapshotArchive(ctx context.Context, opts SnapshotArchiveOptions) (*SnapshotArchive, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().CreateArchive(ctx, opts)
}
func GetSnapshot(ctx context.Context, name string) (*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().Get(ctx, name)
}
func OpenSnapshot(ctx context.Context, reference string) (*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().Open(ctx, reference)
}
func ListSnapshots(ctx context.Context) ([]*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().List(ctx)
}
func ListSnapshotsDir(ctx context.Context, dir string) ([]*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().ListDir(ctx, dir)
}
func RemoveSnapshot(ctx context.Context, reference string, force bool) error {
	local, err := defaultLocalContext()
	if err != nil {
		return err
	}
	return local.Snapshots().Remove(ctx, reference, force)
}
func ReindexSnapshots(ctx context.Context, dir string) (uint32, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return 0, err
	}
	return local.Snapshots().Reindex(ctx, dir)
}
func SaveSnapshot(ctx context.Context, reference, path string, opts SnapshotSaveOptions) error {
	local, err := defaultLocalContext()
	if err != nil {
		return err
	}
	return local.Snapshots().Save(ctx, reference, path, opts)
}
func LoadSnapshot(ctx context.Context, archive, dest string) (*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().Load(ctx, archive, dest)
}
func LoadSnapshotWithBase(ctx context.Context, archive, dest, base string) (*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().LoadWithBase(ctx, archive, dest, base)
}
func LoadSnapshotWithOptions(ctx context.Context, archive string, opts SnapshotLoadOptions) (*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().LoadWithOptions(ctx, archive, opts)
}
func LoadSnapshots(ctx context.Context, archives []string, opts SnapshotLoadOptions) ([]*Snapshot, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().LoadMany(ctx, archives, opts)
}
func SnapshotGroupHead(ctx context.Context, selector string) (*SnapshotHeadUpdate, error) {
	local, err := defaultLocalContext()
	if err != nil {
		return nil, err
	}
	return local.Snapshots().GroupHead(ctx, selector)
}

func snapshotHeadUpdateFromInfo(update *ffi.SnapshotHeadUpdate) *SnapshotHeadUpdate {
	if update == nil {
		return nil
	}
	return &SnapshotHeadUpdate{
		Group:    update.Group,
		Previous: update.Previous,
		Head:     update.Head,
		Reason:   update.Reason,
		Changed:  update.Changed,
	}
}

func cloneSnapshotHeadUpdate(update *SnapshotHeadUpdate) *SnapshotHeadUpdate {
	if update == nil {
		return nil
	}
	copy := *update
	copy.Previous = cloneStringPtr(update.Previous)
	return &copy
}

func normalizeSnapshotScope(scope string) string {
	if scope == "" {
		return SnapshotScopeDisk
	}
	return scope
}

func snapshotVerifyReportFromInfo(info *ffi.SnapshotVerifyReport) *SnapshotVerifyReport {
	report := &SnapshotVerifyReport{
		Digest: info.Digest,
		Path:   info.Path,
		Upper: SnapshotUpperVerifyStatus{
			Kind:      info.Upper.Kind,
			Algorithm: info.Upper.Algorithm,
			Digest:    info.Upper.Digest,
		},
	}
	if info.Checkpoint != nil {
		report.Checkpoint = &SnapshotCheckpointVerifyStatus{
			Kind: info.Checkpoint.Kind,
			Root: info.Checkpoint.Root,
		}
	}
	return report
}

func snapshotStateFromInfo(info *ffi.SnapshotInfo) SnapshotState {
	if info.StateKind == "checkpoint" {
		state := &SnapshotCheckpointState{}
		if info.CheckpointID != nil {
			state.CheckpointID = *info.CheckpointID
		}
		if info.CheckpointManifestDigest != nil {
			state.ManifestDigest = *info.CheckpointManifestDigest
		}
		return SnapshotState{Kind: "checkpoint", Checkpoint: state}
	}
	state := &SnapshotFileState{}
	if info.Format != nil {
		state.Format = *info.Format
	}
	if info.Fstype != nil {
		state.Fstype = *info.Fstype
	}
	if info.UpperFile != nil {
		state.UpperFile = *info.UpperFile
	}
	if info.SizeBytes != nil {
		state.SizeBytes = *info.SizeBytes
	}
	if info.UpperIntegrityAlgorithm != nil {
		state.HasIntegrity = true
		state.Integrity.Algorithm = *info.UpperIntegrityAlgorithm
	}
	if info.UpperIntegrityAlgorithm != nil && *info.UpperIntegrityAlgorithm == "msb-file-merkle-blake3-v1" {
		// Digest remains the compatibility spelling for callers written before
		// Merkle descriptors exposed their structural parameters.
		if info.UpperIntegrityDigest != nil {
			state.Integrity.Digest = *info.UpperIntegrityDigest
		}
		if info.UpperIntegrityRoot != nil {
			state.Integrity.Root = *info.UpperIntegrityRoot
		}
		if info.UpperIntegrityLogicalSize != nil {
			state.Integrity.LogicalSize = *info.UpperIntegrityLogicalSize
		}
		if info.UpperIntegrityLeafSize != nil {
			state.Integrity.LeafSize = *info.UpperIntegrityLeafSize
		}
	} else if info.UpperIntegrityDigest != nil {
		state.Integrity.Digest = *info.UpperIntegrityDigest
	}
	return SnapshotState{Kind: "file", File: state}
}

func cloneSnapshotState(in SnapshotState) SnapshotState {
	out := SnapshotState{Kind: in.Kind}
	if in.File != nil {
		copy := *in.File
		out.File = &copy
	}
	if in.Checkpoint != nil {
		copy := *in.Checkpoint
		out.Checkpoint = &copy
	}
	return out
}

func cloneStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneUint64Ptr(in *uint64) *uint64 {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// SnapshotInfo is a fresh artifact observation, distinct from the resource itself.
type SnapshotInfo struct {
	ID                       string     `json:"id"`
	Name                     *string    `json:"name"`
	Group                    *string    `json:"group"`
	Digest                   string     `json:"digest"`
	ParentDigest             *string    `json:"parent_digest"`
	Scope                    string     `json:"scope"`
	ImageRef                 string     `json:"image_ref"`
	StateKind                string     `json:"state_kind"`
	Format                   *string    `json:"format"`
	Fstype                   *string    `json:"fstype"`
	CheckpointManifestDigest *string    `json:"checkpoint_manifest_digest"`
	SizeBytes                *uint64    `json:"size_bytes"`
	Locality                 string     `json:"locality"`
	Availability             string     `json:"availability"`
	MigrationState           string     `json:"migration_state"`
	MigrationErrorCode       *string    `json:"migration_error_code"`
	CreatedAt                *time.Time `json:"created_at"`
}

func (s *Snapshot) Info(ctx context.Context) (*SnapshotInfo, error) {
	var info SnapshotInfo
	if err := s.inner.Operation(ctx, "info", nil, &info); err != nil {
		return nil, wrapFFI(err)
	}
	return &info, nil
}
func (s *Snapshot) ParentDigest(ctx context.Context) (*string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.ParentDigest, nil
}
func (s *Snapshot) Scope(ctx context.Context) (string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.Scope, nil
}
func (s *Snapshot) ImageRef(ctx context.Context) (string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.ImageRef, nil
}
func (s *Snapshot) StateKind(ctx context.Context) (string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.StateKind, nil
}
func (s *Snapshot) Format(ctx context.Context) (*string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.Format, nil
}
func (s *Snapshot) Fstype(ctx context.Context) (*string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.Fstype, nil
}
func (s *Snapshot) CheckpointManifestDigest(ctx context.Context) (*string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.CheckpointManifestDigest, nil
}
func (s *Snapshot) SizeBytes(ctx context.Context) (*uint64, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.SizeBytes, nil
}
func (s *Snapshot) Locality(ctx context.Context) (string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.Locality, nil
}
func (s *Snapshot) Availability(ctx context.Context) (string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.Availability, nil
}
func (s *Snapshot) MigrationState(ctx context.Context) (string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.MigrationState, nil
}
func (s *Snapshot) MigrationErrorCode(ctx context.Context) (*string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.MigrationErrorCode, nil
}
func (s *Snapshot) CreatedAt(ctx context.Context) (*time.Time, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.CreatedAt, nil
}
func (s *Snapshot) ImageManifestDigest(ctx context.Context) (string, error) {
	info, err := s.metadata(ctx)
	if err != nil {
		return "", err
	}
	return info.ImageManifestDigest, nil
}
func (s *Snapshot) SourceSandbox(ctx context.Context) (*string, error) {
	info, err := s.metadata(ctx)
	if err != nil {
		return nil, err
	}
	return info.SourceSandbox, nil
}

// Snapshot captures this Sandbox identity without selecting a same-name replacement.
func (s *Sandbox) Snapshot(ctx context.Context, name string) (*Snapshot, error) {
	resource, err := s.inner.Snapshot(ctx, name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotFromResource(resource)
}

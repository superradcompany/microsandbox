package microsandbox

import (
	"context"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Snapshot is the factory namespace for snapshot artifact operations.
var Snapshot snapshotFactory

type snapshotFactory struct{}

// SnapshotCreateOptions configures Snapshot.Create.
type SnapshotCreateOptions struct {
	// Snapshot member name; generated when empty.
	Name string
	// Group to install the member in; defaults to the source sandbox's name.
	Group string
	// Source sandbox to snapshot. Disk capture preserves running/paused state. Required.
	FromSandbox string
	// Parent directory to create the artifact in; empty = the default
	// snapshots directory. The group is created under this root.
	DestDir         string
	Labels          map[string]string
	Force           bool
	RecordIntegrity bool
	// Full includes memory and execution state from a running or paused source.
	// False captures disk state from running, paused, stopped, or crashed sources.
	Full bool
}

// SnapshotSaveOptions configures Snapshot.Save.
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

// Snapshot payload scope values, as reported by SnapshotArtifact.Scope
// and SnapshotHandle.Scope.
const (
	SnapshotScopeDisk = "disk"
	SnapshotScopeFull = "full"
)

// SnapshotVerifyReport is returned by SnapshotArtifact.Verify.
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

// SnapshotArtifact is a snapshot artifact on disk.
type SnapshotArtifact struct {
	headUpdate          *SnapshotHeadUpdate
	id                  string
	path                string
	digest              string
	sizeBytes           *uint64
	imageRef            string
	imageManifestDigest string
	scope               string
	state               SnapshotState
	parent              *string
	createdAt           string
	labels              map[string]string
	sourceSandbox       *string
}

func snapshotFromInfo(info *ffi.SnapshotInfo) *SnapshotArtifact {
	return &SnapshotArtifact{
		headUpdate:          snapshotHeadUpdateFromInfo(info.HeadUpdate),
		id:                  info.ID,
		path:                info.Path,
		digest:              info.Digest,
		sizeBytes:           info.SizeBytes,
		imageRef:            info.ImageRef,
		imageManifestDigest: info.ImageManifestDigest,
		scope:               normalizeSnapshotScope(info.Scope),
		state:               snapshotStateFromInfo(info),
		parent:              info.Parent,
		createdAt:           info.CreatedAt,
		labels:              cloneMap(info.Labels),
		sourceSandbox:       info.SourceSandbox,
	}
}

func (s *SnapshotArtifact) Path() string                { return s.path }
func (s *SnapshotArtifact) ID() string                  { return s.id }
func (s *SnapshotArtifact) Digest() string              { return s.digest }
func (s *SnapshotArtifact) SizeBytes() *uint64          { return cloneUint64Ptr(s.sizeBytes) }
func (s *SnapshotArtifact) ImageRef() string            { return s.imageRef }
func (s *SnapshotArtifact) ImageManifestDigest() string { return s.imageManifestDigest }
func (s *SnapshotArtifact) Scope() string               { return s.scope }
func (s *SnapshotArtifact) State() SnapshotState        { return cloneSnapshotState(s.state) }
func (s *SnapshotArtifact) Format() string {
	if s.state.File != nil {
		return s.state.File.Format
	}
	return ""
}
func (s *SnapshotArtifact) Fstype() string {
	if s.state.File != nil {
		return s.state.File.Fstype
	}
	return ""
}
func (s *SnapshotArtifact) Parent() *string           { return cloneStringPtr(s.parent) }
func (s *SnapshotArtifact) CreatedAt() string         { return s.createdAt }
func (s *SnapshotArtifact) Labels() map[string]string { return cloneMap(s.labels) }
func (s *SnapshotArtifact) SourceSandbox() *string    { return cloneStringPtr(s.sourceSandbox) }

// HeadUpdate returns the group head outcome recorded by this capture, if any.
func (s *SnapshotArtifact) HeadUpdate() *SnapshotHeadUpdate {
	return cloneSnapshotHeadUpdate(s.headUpdate)
}

// Verify recomputes recorded content integrity for the snapshot.
func (s *SnapshotArtifact) Verify(ctx context.Context) (*SnapshotVerifyReport, error) {
	report, err := ffi.SnapshotVerify(ctx, s.path)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotVerifyReportFromInfo(report), nil
}

// SnapshotHandle is a lightweight handle backed by the snapshot index.
type SnapshotHandle struct {
	group                    *string
	headUpdate               *SnapshotHeadUpdate
	id                       string
	digest                   string
	name                     *string
	parentDigest             *string
	scope                    string
	imageRef                 string
	stateKind                string
	format                   *string
	fstype                   *string
	checkpointManifestDigest *string
	sizeBytes                *uint64
	locality                 string
	availability             string
	migrationState           string
	migrationErrorCode       *string
	createdAtUnix            int64
	path                     string
}

func snapshotHandleFromInfo(info *ffi.SnapshotHandleInfo) *SnapshotHandle {
	return &SnapshotHandle{
		group:                    info.Group,
		headUpdate:               snapshotHeadUpdateFromInfo(info.HeadUpdate),
		id:                       info.ID,
		digest:                   info.Digest,
		name:                     info.Name,
		parentDigest:             info.ParentDigest,
		scope:                    normalizeSnapshotScope(info.Scope),
		imageRef:                 info.ImageRef,
		stateKind:                info.StateKind,
		format:                   info.Format,
		fstype:                   info.Fstype,
		checkpointManifestDigest: info.CheckpointManifestDigest,
		sizeBytes:                info.SizeBytes,
		locality:                 info.Locality,
		availability:             info.Availability,
		migrationState:           info.MigrationState,
		migrationErrorCode:       info.MigrationErrorCode,
		createdAtUnix:            info.CreatedAtUnix,
		path:                     info.Path,
	}
}

func (h *SnapshotHandle) ID() string     { return h.id }
func (h *SnapshotHandle) Digest() string { return h.digest }
func (h *SnapshotHandle) Name() *string  { return cloneStringPtr(h.name) }

// Group returns the local group containing this indexed snapshot.
func (h *SnapshotHandle) Group() *string { return cloneStringPtr(h.group) }

// HeadUpdate returns the group head outcome recorded by this import, if any.
func (h *SnapshotHandle) HeadUpdate() *SnapshotHeadUpdate {
	return cloneSnapshotHeadUpdate(h.headUpdate)
}
func (h *SnapshotHandle) ParentDigest() *string { return cloneStringPtr(h.parentDigest) }
func (h *SnapshotHandle) Scope() string         { return h.scope }
func (h *SnapshotHandle) ImageRef() string      { return h.imageRef }
func (h *SnapshotHandle) StateKind() string     { return h.stateKind }
func (h *SnapshotHandle) Format() *string       { return cloneStringPtr(h.format) }
func (h *SnapshotHandle) Fstype() *string       { return cloneStringPtr(h.fstype) }
func (h *SnapshotHandle) CheckpointManifestDigest() *string {
	return cloneStringPtr(h.checkpointManifestDigest)
}
func (h *SnapshotHandle) SizeBytes() *uint64          { return cloneUint64Ptr(h.sizeBytes) }
func (h *SnapshotHandle) Locality() string            { return h.locality }
func (h *SnapshotHandle) Availability() string        { return h.availability }
func (h *SnapshotHandle) MigrationState() string      { return h.migrationState }
func (h *SnapshotHandle) MigrationErrorCode() *string { return cloneStringPtr(h.migrationErrorCode) }
func (h *SnapshotHandle) Path() string                { return h.path }
func (h *SnapshotHandle) CreatedAt() time.Time        { return time.Unix(h.createdAtUnix, 0) }

func (h *SnapshotHandle) Open(ctx context.Context) (*SnapshotArtifact, error) {
	return Snapshot.Open(ctx, h.path)
}

func (h *SnapshotHandle) Remove(ctx context.Context, force bool) error {
	// Copies in different groups share a digest; the handle owns one exact artifact path.
	return Snapshot.Remove(ctx, h.path, force)
}

func (snapshotFactory) Create(ctx context.Context, opts SnapshotCreateOptions) (*SnapshotArtifact, error) {
	if opts.FromSandbox == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot create requires a source sandbox (FromSandbox)"}
	}
	info, err := ffi.SnapshotCreate(ctx, opts.FromSandbox, ffi.SnapshotCreateOptions{
		Name:            opts.Name,
		Group:           opts.Group,
		DestDir:         opts.DestDir,
		Labels:          opts.Labels,
		Force:           opts.Force,
		RecordIntegrity: opts.RecordIntegrity,
		Full:            opts.Full,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotFromInfo(info), nil
}

// CreateArchive captures a disk or full snapshot directly into one archive file.
// It does not create an installed snapshot directory or index row.
func (snapshotFactory) CreateArchive(ctx context.Context, opts SnapshotArchiveOptions) (*SnapshotArchive, error) {
	if opts.FromSandbox == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot archive create requires a source sandbox (FromSandbox)"}
	}
	if opts.ArchivePath == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot archive create requires ArchivePath"}
	}
	info, err := ffi.SnapshotCreateArchive(ctx, opts.FromSandbox, opts.ArchivePath, ffi.SnapshotCreateOptions{
		Name:            opts.Name,
		Group:           opts.Group,
		Labels:          opts.Labels,
		Force:           opts.Force,
		RecordIntegrity: opts.RecordIntegrity,
		Full:            opts.Full,
	}, opts.PlainTar)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &SnapshotArchive{
		id:               info.ID,
		descriptorDigest: info.DescriptorDigest,
		path:             info.Path,
	}, nil
}

func (snapshotFactory) Open(ctx context.Context, pathOrName string) (*SnapshotArtifact, error) {
	info, err := ffi.SnapshotOpen(ctx, pathOrName)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotFromInfo(info), nil
}

func (snapshotFactory) Get(ctx context.Context, nameOrDigest string) (*SnapshotHandle, error) {
	info, err := ffi.SnapshotGet(ctx, nameOrDigest)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotHandleFromInfo(info), nil
}

func (snapshotFactory) List(ctx context.Context) ([]*SnapshotHandle, error) {
	infos, err := ffi.SnapshotList(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make([]*SnapshotHandle, len(infos))
	for i, info := range infos {
		out[i] = snapshotHandleFromInfo(info)
	}
	return out, nil
}

func (snapshotFactory) ListDir(ctx context.Context, dir string) ([]*SnapshotArtifact, error) {
	infos, err := ffi.SnapshotListDir(ctx, dir)
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make([]*SnapshotArtifact, len(infos))
	for i, info := range infos {
		out[i] = snapshotFromInfo(info)
	}
	return out, nil
}

func (snapshotFactory) Remove(ctx context.Context, pathOrName string, force bool) error {
	return wrapFFI(ffi.SnapshotRemove(ctx, pathOrName, force))
}

func (snapshotFactory) Reindex(ctx context.Context, dir string) (uint32, error) {
	n, err := ffi.SnapshotReindex(ctx, dir)
	return n, wrapFFI(err)
}

func (snapshotFactory) Save(ctx context.Context, nameOrPath, outPath string, opts SnapshotSaveOptions) error {
	return wrapFFI(ffi.SnapshotSave(ctx, nameOrPath, outPath, ffi.SnapshotSaveOptions{
		WithParents: opts.WithParents,
		WithImage:   opts.WithImage,
		PlainTar:    opts.PlainTar,
		Since:       opts.Since,
		LastLayers:  opts.LastLayers,
	}))
}

func (snapshotFactory) Load(ctx context.Context, archive, dest string) (*SnapshotHandle, error) {
	info, err := ffi.SnapshotLoad(ctx, archive, dest)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotHandleFromInfo(info), nil
}

// LoadWithBase imports a dependent archive into a complete locally owned snapshot closure.
func (snapshotFactory) LoadWithBase(ctx context.Context, archive, dest, base string) (*SnapshotHandle, error) {
	info, err := ffi.SnapshotLoadWithBase(ctx, archive, dest, base)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotHandleFromInfo(info), nil
}

// LoadWithOptions imports an archive into a selected or generated group.
func (snapshotFactory) LoadWithOptions(ctx context.Context, archive string, opts SnapshotLoadOptions) (*SnapshotHandle, error) {
	info, err := ffi.SnapshotLoadWithOptions(ctx, archive, ffi.SnapshotLoadOptions{
		Dest:    opts.Dest,
		Base:    opts.Base,
		Group:   opts.Group,
		SetHead: opts.SetHead,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotHandleFromInfo(info), nil
}

// LoadMany imports archives together into one group, resolving dependencies regardless of input order.
func (snapshotFactory) LoadMany(ctx context.Context, archives []string, opts SnapshotLoadOptions) ([]*SnapshotHandle, error) {
	infos, err := ffi.SnapshotLoadMany(ctx, archives, ffi.SnapshotLoadOptions{
		Dest:    opts.Dest,
		Base:    opts.Base,
		Group:   opts.Group,
		SetHead: opts.SetHead,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	handles := make([]*SnapshotHandle, len(infos))
	for index, info := range infos {
		handles[index] = snapshotHandleFromInfo(info)
	}
	return handles, nil
}

// GroupHead reads a group head, or selects a group:member as its head.
func (snapshotFactory) GroupHead(ctx context.Context, selector string) (*SnapshotHeadUpdate, error) {
	update, err := ffi.SnapshotGroupHead(ctx, selector)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotHeadUpdateFromInfo(update), nil
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

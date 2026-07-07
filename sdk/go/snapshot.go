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
	// Snapshot name, resolved under the default snapshots directory
	// (or under DestDir when set).
	Name string
	// Source sandbox to snapshot. Must be stopped. Required.
	FromSandbox string
	// Parent directory to create the artifact in; empty = the default
	// snapshots directory. The artifact lands at DestDir/<name>.
	DestDir         string
	Labels          map[string]string
	Force           bool
	RecordIntegrity bool
	Resumable       bool
}

// SnapshotSaveOptions configures Snapshot.Save.
type SnapshotSaveOptions struct {
	WithParents bool
	WithImage   bool
	PlainTar    bool
}

// Snapshot payload scope values, as reported by SnapshotArtifact.Scope
// and SnapshotHandle.Scope.
const (
	SnapshotScopeDisk      = "disk"
	SnapshotScopeResumable = "resumable"
)

// SnapshotVerifyReport is returned by SnapshotArtifact.Verify.
type SnapshotVerifyReport struct {
	Digest string
	Path   string
	Upper  SnapshotUpperVerifyStatus
}

type SnapshotUpperVerifyStatus struct {
	Kind      string
	Algorithm string
	Digest    string
}

// SnapshotArtifact is a snapshot artifact on disk.
type SnapshotArtifact struct {
	path                string
	digest              string
	sizeBytes           uint64
	imageRef            string
	imageManifestDigest string
	scope               string
	format              string
	fstype              string
	parent              *string
	createdAt           string
	labels              map[string]string
	sourceSandbox       *string
}

func snapshotFromInfo(info *ffi.SnapshotInfo) *SnapshotArtifact {
	return &SnapshotArtifact{
		path:                info.Path,
		digest:              info.Digest,
		sizeBytes:           info.SizeBytes,
		imageRef:            info.ImageRef,
		imageManifestDigest: info.ImageManifestDigest,
		scope:               normalizeSnapshotScope(info.Scope),
		format:              info.Format,
		fstype:              info.Fstype,
		parent:              info.Parent,
		createdAt:           info.CreatedAt,
		labels:              cloneMap(info.Labels),
		sourceSandbox:       info.SourceSandbox,
	}
}

func (s *SnapshotArtifact) Path() string                { return s.path }
func (s *SnapshotArtifact) Digest() string              { return s.digest }
func (s *SnapshotArtifact) SizeBytes() uint64           { return s.sizeBytes }
func (s *SnapshotArtifact) ImageRef() string            { return s.imageRef }
func (s *SnapshotArtifact) ImageManifestDigest() string { return s.imageManifestDigest }
func (s *SnapshotArtifact) Scope() string               { return s.scope }
func (s *SnapshotArtifact) Format() string              { return s.format }
func (s *SnapshotArtifact) Fstype() string              { return s.fstype }
func (s *SnapshotArtifact) Parent() *string             { return cloneStringPtr(s.parent) }
func (s *SnapshotArtifact) CreatedAt() string           { return s.createdAt }
func (s *SnapshotArtifact) Labels() map[string]string   { return cloneMap(s.labels) }
func (s *SnapshotArtifact) SourceSandbox() *string      { return cloneStringPtr(s.sourceSandbox) }

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
	digest        string
	name          *string
	parentDigest  *string
	scope         string
	imageRef      string
	format        string
	sizeBytes     *uint64
	createdAtUnix int64
	path          string
}

func snapshotHandleFromInfo(info *ffi.SnapshotHandleInfo) *SnapshotHandle {
	return &SnapshotHandle{
		digest:        info.Digest,
		name:          info.Name,
		parentDigest:  info.ParentDigest,
		scope:         normalizeSnapshotScope(info.Scope),
		imageRef:      info.ImageRef,
		format:        info.Format,
		sizeBytes:     info.SizeBytes,
		createdAtUnix: info.CreatedAtUnix,
		path:          info.Path,
	}
}

func (h *SnapshotHandle) Digest() string        { return h.digest }
func (h *SnapshotHandle) Name() *string         { return cloneStringPtr(h.name) }
func (h *SnapshotHandle) ParentDigest() *string { return cloneStringPtr(h.parentDigest) }
func (h *SnapshotHandle) Scope() string         { return h.scope }
func (h *SnapshotHandle) ImageRef() string      { return h.imageRef }
func (h *SnapshotHandle) Format() string        { return h.format }
func (h *SnapshotHandle) SizeBytes() *uint64    { return cloneUint64Ptr(h.sizeBytes) }
func (h *SnapshotHandle) Path() string          { return h.path }
func (h *SnapshotHandle) CreatedAt() time.Time  { return time.Unix(h.createdAtUnix, 0) }

func (h *SnapshotHandle) Open(ctx context.Context) (*SnapshotArtifact, error) {
	return Snapshot.Open(ctx, h.path)
}

func (h *SnapshotHandle) Remove(ctx context.Context, force bool) error {
	return Snapshot.Remove(ctx, h.digest, force)
}

func (snapshotFactory) Create(ctx context.Context, opts SnapshotCreateOptions) (*SnapshotArtifact, error) {
	if opts.Name == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot create requires a non-empty Name"}
	}
	if opts.FromSandbox == "" {
		return nil, &Error{Kind: ErrInvalidConfig, Message: "snapshot create requires a source sandbox (FromSandbox)"}
	}
	info, err := ffi.SnapshotCreate(ctx, opts.FromSandbox, ffi.SnapshotCreateOptions{
		Name:            opts.Name,
		DestDir:         opts.DestDir,
		Labels:          opts.Labels,
		Force:           opts.Force,
		RecordIntegrity: opts.RecordIntegrity,
		Resumable:       opts.Resumable,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotFromInfo(info), nil
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
	}))
}

func (snapshotFactory) Load(ctx context.Context, archive, dest string) (*SnapshotHandle, error) {
	info, err := ffi.SnapshotLoad(ctx, archive, dest)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return snapshotHandleFromInfo(info), nil
}

func normalizeSnapshotScope(scope string) string {
	if scope == "" {
		return SnapshotScopeDisk
	}
	return scope
}

func snapshotVerifyReportFromInfo(info *ffi.SnapshotVerifyReport) *SnapshotVerifyReport {
	return &SnapshotVerifyReport{
		Digest: info.Digest,
		Path:   info.Path,
		Upper: SnapshotUpperVerifyStatus{
			Kind:      info.Upper.Kind,
			Algorithm: info.Upper.Algorithm,
			Digest:    info.Upper.Digest,
		},
	}
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

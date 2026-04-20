package microsandbox

import (
	"context"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Volume is a named persistent volume. It is a handle to runtime state by
// name; there is no process or Rust-side resource to release.
type Volume struct {
	name string
}

// Name returns the volume's name.
func (v *Volume) Name() string { return v.name }

// Remove deletes this volume. All sandboxes using it must be stopped.
func (v *Volume) Remove(ctx context.Context) error {
	return RemoveVolume(ctx, v.name)
}

// CreateVolume creates a named volume.
func CreateVolume(ctx context.Context, name string, opts ...VolumeOption) (*Volume, error) {
	o := VolumeConfig{}
	for _, opt := range opts {
		opt(&o)
	}
	if err := ffi.CreateVolume(ctx, name, uint32(o.QuotaMiB)); err != nil {
		return nil, wrapFFI(err)
	}
	return &Volume{name: name}, nil
}

// ListVolumes returns all known volumes.
func ListVolumes(ctx context.Context) ([]*Volume, error) {
	names, err := ffi.ListVolumes(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make([]*Volume, len(names))
	for i, n := range names {
		out[i] = &Volume{name: n}
	}
	return out, nil
}

// RemoveVolume removes a volume by name.
func RemoveVolume(ctx context.Context, name string) error {
	return wrapFFI(ffi.RemoveVolume(ctx, name))
}

// ---------------------------------------------------------------------------
// VolumeHandle — metadata reference returned by GetVolume
// ---------------------------------------------------------------------------

// VolumeHandle carries metadata for a named volume. Obtain via GetVolume.
type VolumeHandle struct {
	name          string
	quotaMiB      *uint32
	usedBytes     uint64
	labels        map[string]string
	createdAtUnix *int64
}

// Name returns the volume name.
func (h *VolumeHandle) Name() string { return h.name }

// QuotaMiB returns the quota in MiB, or nil if unlimited.
func (h *VolumeHandle) QuotaMiB() *uint32 { return h.quotaMiB }

// UsedBytes returns the amount of space used by the volume in bytes.
func (h *VolumeHandle) UsedBytes() uint64 { return h.usedBytes }

// Labels returns the labels attached to this volume.
func (h *VolumeHandle) Labels() map[string]string { return h.labels }

// CreatedAt returns the creation timestamp, or the zero value if unknown.
func (h *VolumeHandle) CreatedAt() time.Time {
	if h.createdAtUnix == nil {
		return time.Time{}
	}
	return time.Unix(*h.createdAtUnix, 0)
}

// Remove deletes this volume. All sandboxes using it must be stopped.
func (h *VolumeHandle) Remove(ctx context.Context) error {
	return RemoveVolume(ctx, h.name)
}

// GetVolume looks up a volume by name and returns its metadata.
func GetVolume(ctx context.Context, name string) (*VolumeHandle, error) {
	info, err := ffi.GetVolume(ctx, name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &VolumeHandle{
		name:          info.Name,
		quotaMiB:      info.QuotaMiB,
		usedBytes:     info.UsedBytes,
		labels:        info.Labels,
		createdAtUnix: info.CreatedAtUnix,
	}, nil
}

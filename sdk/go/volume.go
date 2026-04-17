package microsandbox

import (
	"context"

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

// NewVolume creates a named volume.
func NewVolume(ctx context.Context, name string, opts ...VolumeOption) (*Volume, error) {
	o := VolumeOptions{}
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

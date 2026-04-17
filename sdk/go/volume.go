package microsandbox

import (
	"context"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Volume represents a persistent named volume that can be mounted in sandboxes.
type Volume struct {
	name string
	ffi  ffi.FFI
}

// Name returns the volume's name.
func (v *Volume) Name() string {
	return v.name
}

// Remove deletes the volume.
// All sandboxes using this volume must be stopped first.
func (v *Volume) Remove(ctx context.Context) error {
	return removeVolumeInternal(ctx, v.ffi, v.name)
}

// NewVolume creates a new named volume with optional configuration.
func NewVolume(ctx context.Context, name string, opts ...VolumeOption) (*Volume, error) {
	return newVolumeInternal(ctx, ffi.NewRealFFI(), name, opts...)
}

func newVolumeInternal(ctx context.Context, f ffi.FFI, name string, opts ...VolumeOption) (*Volume, error) {
	options := &VolumeOptions{}
	for _, opt := range opts {
		opt(options)
	}

	err := f.VolumeCreate(ctx, name, options.QuotaMiB)
	if err != nil {
		return nil, WrapErrorf(ErrVolumeAlreadyExists, err, "failed to create volume %q", name)
	}

	return &Volume{name: name, ffi: f}, nil
}

// ListVolumes returns all named volumes.
func ListVolumes(ctx context.Context) ([]*Volume, error) {
	return listVolumesInternal(ctx, ffi.NewRealFFI())
}

func listVolumesInternal(ctx context.Context, f ffi.FFI) ([]*Volume, error) {
	names, err := f.VolumeList(ctx)
	if err != nil {
		return nil, WrapError(ErrInternal, err, "failed to list volumes")
	}

	volumes := make([]*Volume, len(names))
	for i, name := range names {
		volumes[i] = &Volume{name: name, ffi: f}
	}
	return volumes, nil
}

// RemoveVolume removes a volume by name.
func RemoveVolume(ctx context.Context, name string) error {
	return removeVolumeInternal(ctx, ffi.NewRealFFI(), name)
}

func removeVolumeInternal(ctx context.Context, f ffi.FFI, name string) error {
	err := f.VolumeRemove(ctx, name)
	if err != nil {
		return WrapErrorf(ErrVolumeNotFound, err, "failed to remove volume %q", name)
	}
	return nil
}

// GetVolume retrieves an existing volume by name.
// Returns ErrVolumeNotFound if the volume does not exist.
func GetVolume(ctx context.Context, name string) (*Volume, error) {
	volumes, err := ListVolumes(ctx)
	if err != nil {
		return nil, err
	}

	for _, v := range volumes {
		if v.name == name {
			return v, nil
		}
	}

	return nil, NewErrorf(ErrVolumeNotFound, "volume %q not found", name)
}

// VolumeExists checks if a volume exists.
func VolumeExists(ctx context.Context, name string) (bool, error) {
	_, err := GetVolume(ctx, name)
	if err != nil {
		if IsKind(err, ErrVolumeNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

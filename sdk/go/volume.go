package microsandbox

import (
	"context"
	"os"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Volume is a named persistent volume. It is a handle to runtime state by
// name; there is no process or Rust-side resource to release.
type Volume struct {
	name string
	path string
}

// Name returns the volume's name.
func (v *Volume) Name() string { return v.name }

// Path returns the host filesystem path of the volume's data directory.
// Always empty for volumes returned by CreateVolume or ListVolumes; use
// GetVolume to retrieve path metadata.
func (v *Volume) Path() string { return v.path }

// FS returns a VolumeFs for direct host-side file operations on this volume.
func (v *Volume) FS() *VolumeFs { return &VolumeFs{root: v.path} }

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
	path          string
	quotaMiB      *uint32
	usedBytes     uint64
	labels        map[string]string
	createdAtUnix *int64
}

// Name returns the volume name.
func (h *VolumeHandle) Name() string { return h.name }

// Path returns the host filesystem path of the volume's data directory.
func (h *VolumeHandle) Path() string { return h.path }

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

// FS returns a VolumeFs for direct host-side file operations on this volume.
func (h *VolumeHandle) FS() *VolumeFs { return &VolumeFs{root: h.path} }

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
		path:          info.Path,
		quotaMiB:      info.QuotaMiB,
		usedBytes:     info.UsedBytes,
		labels:        info.Labels,
		createdAtUnix: info.CreatedAtUnix,
	}, nil
}

// ---------------------------------------------------------------------------
// VolumeFs — host-side file operations on a volume directory
// ---------------------------------------------------------------------------

// VolumeFs provides direct file operations on a volume's host directory.
// All operations work directly on the host filesystem — no agent protocol.
// Obtain via Volume.FS() or VolumeHandle.FS().
type VolumeFs struct {
	root string
}

// Root returns the absolute host path of the volume's data directory.
func (fs *VolumeFs) Root() string { return fs.root }

// Read reads the contents of a file relative to the volume root.
func (fs *VolumeFs) Read(relPath string) ([]byte, error) {
	return os.ReadFile(fs.abs(relPath))
}

// ReadString reads a file and returns its contents as a string.
func (fs *VolumeFs) ReadString(relPath string) (string, error) {
	data, err := fs.Read(relPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Write writes data to a file, creating or truncating it.
func (fs *VolumeFs) Write(relPath string, data []byte) error {
	return os.WriteFile(fs.abs(relPath), data, 0o644)
}

// WriteString writes a string to a file.
func (fs *VolumeFs) WriteString(relPath, content string) error {
	return fs.Write(relPath, []byte(content))
}

// Mkdir creates a directory and all missing parents.
func (fs *VolumeFs) Mkdir(relPath string) error {
	return os.MkdirAll(fs.abs(relPath), 0o755)
}

// Remove deletes a file or empty directory.
func (fs *VolumeFs) Remove(relPath string) error {
	return os.Remove(fs.abs(relPath))
}

// RemoveAll deletes a path and any children it contains.
func (fs *VolumeFs) RemoveAll(relPath string) error {
	return os.RemoveAll(fs.abs(relPath))
}

// Exists reports whether a file or directory exists at the given path.
func (fs *VolumeFs) Exists(relPath string) (bool, error) {
	_, err := os.Stat(fs.abs(relPath))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (fs *VolumeFs) abs(rel string) string {
	return fs.root + "/" + rel
}

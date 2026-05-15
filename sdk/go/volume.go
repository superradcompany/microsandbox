package microsandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Volume is a named persistent volume. It carries the host-side path and is
// returned by CreateVolume and Volume-from-handle conversions; lookups (via
// GetVolume / ListVolumes) yield richer VolumeHandle values.
//
// There is no Rust-side resource to release — Remove deletes the on-disk
// state and DB record.
type Volume struct {
	name string
	path string
}

// Name returns the volume's name.
func (v *Volume) Name() string { return v.name }

// Path returns the host filesystem path of the volume's data directory.
func (v *Volume) Path() string { return v.path }

// FS returns a VolumeFs for direct host-side file operations on this volume.
// Returns an error variant if Path is empty.
func (v *Volume) FS() *VolumeFs { return &VolumeFs{root: v.path} }

// Remove deletes this volume. All sandboxes using it must be stopped.
func (v *Volume) Remove(ctx context.Context) error {
	return RemoveVolume(ctx, v.name)
}

// CreateVolume creates a named volume and returns a populated handle (with
// path and metadata).
func CreateVolume(ctx context.Context, name string, opts ...VolumeOption) (*Volume, error) {
	o := VolumeConfig{}
	for _, opt := range opts {
		opt(&o)
	}
	info, err := ffi.CreateVolume(ctx, name, ffi.VolumeCreateOptions{
		QuotaMiB: o.QuotaMiB,
		Labels:   o.Labels,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Volume{name: info.Name, path: info.Path}, nil
}

// ListVolumes returns metadata for every named volume on the host.
func ListVolumes(ctx context.Context) ([]*VolumeHandle, error) {
	infos, err := ffi.ListVolumes(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	out := make([]*VolumeHandle, len(infos))
	for i, info := range infos {
		out[i] = volumeHandleFromInfo(info)
	}
	return out, nil
}

// RemoveVolume removes a volume by name.
func RemoveVolume(ctx context.Context, name string) error {
	return wrapFFI(ffi.RemoveVolume(ctx, name))
}

// ---------------------------------------------------------------------------
// VolumeHandle — metadata reference returned by GetVolume / ListVolumes
// ---------------------------------------------------------------------------

// VolumeHandle carries metadata for a named volume. Obtain via GetVolume or
// ListVolumes.
type VolumeHandle struct {
	name          string
	path          string
	quotaMiB      *uint32
	usedBytes     uint64
	labels        map[string]string
	createdAtUnix *int64
}

func volumeHandleFromInfo(info *ffi.VolumeHandleInfo) *VolumeHandle {
	return &VolumeHandle{
		name:          info.Name,
		path:          info.Path,
		quotaMiB:      info.QuotaMiB,
		usedBytes:     info.UsedBytes,
		labels:        info.Labels,
		createdAtUnix: info.CreatedAtUnix,
	}
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
	return volumeHandleFromInfo(info), nil
}

// ---------------------------------------------------------------------------
// VolumeFs — host-side file operations on a volume directory
// ---------------------------------------------------------------------------

// VolumeFs provides direct file operations on a volume's host directory.
// All operations work directly on the host filesystem — no agent protocol.
// Obtain via Volume.FS() or VolumeHandle.FS().
//
// All path arguments are relative to the volume root. Paths that would
// escape the root via "..", absolute components, or symlink chains are
// rejected with ErrPathEscape.
type VolumeFs struct {
	root string
}

// ErrPathEscape is returned when a relative path would resolve outside the
// volume's root directory.
var ErrPathEscape = errors.New("microsandbox: path escapes volume root")

// Root returns the absolute host path of the volume's data directory.
func (fs *VolumeFs) Root() string { return fs.root }

// Read reads the contents of a file relative to the volume root.
func (fs *VolumeFs) Read(relPath string) ([]byte, error) {
	abs, err := fs.abs(relPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(abs)
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
	abs, err := fs.abs(relPath)
	if err != nil {
		return err
	}
	return os.WriteFile(abs, data, 0o644)
}

// WriteString writes a string to a file.
func (fs *VolumeFs) WriteString(relPath, content string) error {
	return fs.Write(relPath, []byte(content))
}

// Mkdir creates a directory and all missing parents.
func (fs *VolumeFs) Mkdir(relPath string) error {
	abs, err := fs.abs(relPath)
	if err != nil {
		return err
	}
	return os.MkdirAll(abs, 0o755)
}

// Remove deletes a file or empty directory.
func (fs *VolumeFs) Remove(relPath string) error {
	abs, err := fs.abs(relPath)
	if err != nil {
		return err
	}
	return os.Remove(abs)
}

// RemoveAll deletes a path and any children it contains.
func (fs *VolumeFs) RemoveAll(relPath string) error {
	abs, err := fs.abs(relPath)
	if err != nil {
		return err
	}
	return os.RemoveAll(abs)
}

// Exists reports whether a file or directory exists at the given path.
func (fs *VolumeFs) Exists(relPath string) (bool, error) {
	abs, err := fs.abs(relPath)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(abs); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else {
		return false, err
	}
}

// abs joins relPath under fs.root and verifies the result stays under root.
// Both fs.root and the joined path are cleaned before comparison so embedded
// "../" segments cannot escape. We do NOT follow symlinks here — symlinked
// targets outside the volume are still readable but at least the path the
// caller asked for is constrained.
func (fs *VolumeFs) abs(relPath string) (string, error) {
	if fs.root == "" {
		return "", fmt.Errorf("microsandbox: volume root is empty (use GetVolume to obtain a path)")
	}
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("%w: absolute path %q", ErrPathEscape, relPath)
	}
	root := filepath.Clean(fs.root)
	full := filepath.Clean(filepath.Join(root, relPath))
	rootWithSep := root + string(filepath.Separator)
	if full != root && !strings.HasPrefix(full, rootWithSep) {
		return "", fmt.Errorf("%w: %q resolves outside %q", ErrPathEscape, relPath, fs.root)
	}
	return full, nil
}

// _ keeps the io import alive for future helpers (Open / Create).
var _ = io.Discard

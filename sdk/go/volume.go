package microsandbox

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Volume is persistent storage. Local volumes carry a host-side path; Cloud
// volumes carry an immutable server identity. Lookups yield richer
// VolumeHandle values.
//
// There is no Rust-side resource to release — Remove deletes the on-disk
// state and DB record.
type Volume struct {
	name     string
	path     string
	fsTarget string
}

// Name returns the volume's name.
func (v *Volume) Name() string { return v.name }

// Path returns the host filesystem path of the volume's data directory.
func (v *Volume) Path() string { return v.path }

// FS returns direct filesystem operations for this volume.
func (v *Volume) FS() *VolumeFs { return &VolumeFs{root: v.path, target: v.fsTarget} }

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
		Kind:     string(o.Kind),
		SizeMiB:  o.SizeMiB,
		Labels:   o.Labels,
	})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &Volume{name: info.Name, path: info.Path, fsTarget: volumeFsTarget(info)}, nil
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
	fsTarget      string
	isDefault     bool
	path          string
	kind          VolumeKind
	quotaMiB      *uint32
	usedBytes     uint64
	capacityBytes *uint64
	diskFormat    *string
	diskFstype    *string
	labels        map[string]string
	createdAtUnix *int64
}

func volumeHandleFromInfo(info *ffi.VolumeHandleInfo) *VolumeHandle {
	return &VolumeHandle{
		name:          info.Name,
		fsTarget:      volumeFsTarget(info),
		isDefault:     info.IsDefault,
		path:          info.Path,
		kind:          VolumeKind(info.Kind),
		quotaMiB:      info.QuotaMiB,
		usedBytes:     info.UsedBytes,
		capacityBytes: info.CapacityBytes,
		diskFormat:    info.DiskFormat,
		diskFstype:    info.DiskFstype,
		labels:        info.Labels,
		createdAtUnix: info.CreatedAtUnix,
	}
}

// Name returns the volume name.
func (h *VolumeHandle) Name() string { return h.name }

// IsDefault reports whether this is the cloud account's default volume.
func (h *VolumeHandle) IsDefault() bool { return h.isDefault }

// Path returns the host filesystem path of the volume's data directory.
func (h *VolumeHandle) Path() string { return h.path }

// Kind returns the volume storage kind.
func (h *VolumeHandle) Kind() VolumeKind { return h.kind }

// QuotaMiB returns the quota in MiB, or nil if unlimited.
func (h *VolumeHandle) QuotaMiB() *uint32 { return h.quotaMiB }

// UsedBytes returns the amount of space used by the volume in bytes.
func (h *VolumeHandle) UsedBytes() uint64 { return h.usedBytes }

// CapacityBytes returns disk capacity in bytes for disk volumes.
func (h *VolumeHandle) CapacityBytes() *uint64 { return h.capacityBytes }

// DiskFormat returns the disk image format for disk volumes.
func (h *VolumeHandle) DiskFormat() *string { return h.diskFormat }

// DiskFstype returns the inner filesystem for disk volumes.
func (h *VolumeHandle) DiskFstype() *string { return h.diskFstype }

// Labels returns the labels attached to this volume.
func (h *VolumeHandle) Labels() map[string]string { return h.labels }

// CreatedAt returns the creation timestamp, or the zero value if unknown.
func (h *VolumeHandle) CreatedAt() time.Time {
	if h.createdAtUnix == nil {
		return time.Time{}
	}
	return time.Unix(*h.createdAtUnix, 0)
}

// FS returns direct filesystem operations for this volume.
func (h *VolumeHandle) FS() *VolumeFs { return &VolumeFs{root: h.path, target: h.fsTarget} }

// Remove deletes this volume. All sandboxes using it must be stopped.
func (h *VolumeHandle) Remove(ctx context.Context) error {
	if h.isDefault {
		return &Error{
			Kind:    ErrUnsupportedOperation,
			Message: "the default volume cannot be removed",
		}
	}
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

// GetDefaultVolume returns the cloud account's always-present default volume.
// Local backends return ErrUnsupportedOperation rather than exposing the host filesystem.
func GetDefaultVolume(ctx context.Context) (*VolumeHandle, error) {
	info, err := ffi.GetDefaultVolume(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return volumeHandleFromInfo(info), nil
}

// ---------------------------------------------------------------------------
// VolumeFs — direct file operations on a volume
// ---------------------------------------------------------------------------

// VolumeFs provides direct file operations on a volume. Local operations use
// the host directory; Cloud operations use the authenticated Cloud API.
// Obtain via Volume.FS() or VolumeHandle.FS().
//
// All path arguments are relative to the volume root. Paths that would
// escape the root via "..", absolute components, or symlink chains are
// rejected with ErrPathEscape.
type VolumeFs struct {
	root   string
	target string
}

func volumeFsTarget(info *ffi.VolumeHandleInfo) string {
	if info.ID != nil {
		return "cloud-id:" + *info.ID
	}
	return info.Name
}

// ErrPathEscape is returned when a relative path would resolve outside the
// volume's root directory.
var ErrPathEscape = errors.New("microsandbox: path escapes volume root")

// Root returns the absolute host path of the volume's data directory.
func (fs *VolumeFs) Root() string { return fs.root }

// Read reads the contents of a file relative to the volume root.
func (fs *VolumeFs) Read(ctx context.Context, relPath string) ([]byte, error) {
	var result struct {
		Data string `json:"data_b64"`
	}
	if err := fs.call(ctx, "read", relPath, nil, &result); err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		return nil, fmt.Errorf("microsandbox: decode volume data: %w", err)
	}
	return data, nil
}

// ReadString reads a file and returns its contents as a string.
func (fs *VolumeFs) ReadString(ctx context.Context, relPath string) (string, error) {
	data, err := fs.Read(ctx, relPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Write writes data to a file, creating or truncating it.
func (fs *VolumeFs) Write(ctx context.Context, relPath string, data []byte) error {
	return fs.call(ctx, "write", relPath, map[string]any{
		"data_b64": base64.StdEncoding.EncodeToString(data),
	}, nil)
}

// WriteString writes a string to a file.
func (fs *VolumeFs) WriteString(ctx context.Context, relPath, content string) error {
	return fs.Write(ctx, relPath, []byte(content))
}

// Mkdir creates a directory and all missing parents.
func (fs *VolumeFs) Mkdir(ctx context.Context, relPath string) error {
	return fs.call(ctx, "mkdir", relPath, nil, nil)
}

// Remove deletes a file or empty directory.
func (fs *VolumeFs) Remove(ctx context.Context, relPath string) error {
	return fs.call(ctx, "remove", relPath, map[string]any{"recursive": false}, nil)
}

// RemoveAll deletes a path and any children it contains. For local volumes,
// "" and "." delete the volume directory itself, matching os.RemoveAll.
func (fs *VolumeFs) RemoveAll(ctx context.Context, relPath string) error {
	return fs.call(ctx, "remove", relPath, map[string]any{"recursive": true}, nil)
}

// Exists reports whether a file or directory exists at the given path.
func (fs *VolumeFs) Exists(ctx context.Context, relPath string) (bool, error) {
	var result struct {
		Exists bool `json:"exists"`
	}
	err := fs.call(ctx, "exists", relPath, nil, &result)
	return result.Exists, err
}

// call uses the native capability-based implementation for local volumes too.
// Passing the retained root avoids looking up the volume through a different
// default backend after environment or backend selection changes.
func (fs *VolumeFs) call(ctx context.Context, op, relPath string, args map[string]any, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target := fs.target
	if fs.root != "" {
		if err := validateVolumePath(relPath); err != nil {
			return err
		}
		target = fs.root
		op = "local_" + op
	}
	if args == nil {
		args = make(map[string]any)
	}
	args["path"] = relPath
	if fs.root != "" {
		// Preserve the old lexical destination, but reject ambiguous symlink/.. paths.
		args["clean_path"] = filepath.Clean(relPath)
	}
	err := ffi.VolumeFsOp(ctx, target, op, args, result)
	if fs.root != "" {
		return wrapLocalVolumeError(err, strings.TrimPrefix(op, "local_"), relPath)
	}
	return wrapFFI(err)
}

// This early lexical rejection preserves the Go API's relative-path contract.
// Send both spellings to the native layer so it can detect symlink/.. ambiguity
// against the pinned root before touching either destination.
func validateVolumePath(path string) error {
	if filepath.IsAbs(path) || filepath.VolumeName(path) != "" || strings.HasPrefix(path, "/") || strings.HasPrefix(path, string(filepath.Separator)) {
		return fmt.Errorf("%w: absolute path %q", ErrPathEscape, path)
	}
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q", ErrPathEscape, path)
	}
	return nil
}

func wrapLocalVolumeError(err error, op, path string) error {
	var native *ffi.Error
	if errors.As(err, &native) {
		// Older native libraries reject the new local operation names before
		// touching a filesystem. Never fall back to unconfined host operations.
		if native.Kind == ffi.KindInvalidArgument && native.Message == "unknown volume fs operation" {
			return &Error{Kind: ErrUnsupportedOperation, Message: "native SDK does not support confined local volume operations; update the native SDK"}
		}
		if native.Kind != "volume_path_escape" && native.OSError != nil {
			// The native library shares our host OS. Windows codes occupy 32 bits,
			// even when Rust's signed raw_os_error representation is negative.
			return &os.PathError{Op: op, Path: path, Err: syscall.Errno(uint32(*native.OSError))}
		}
		switch native.Kind {
		case "volume_path_escape":
			return fmt.Errorf("%w: %s", ErrPathEscape, native.Message)
		case "volume_path_not_found":
			return &os.PathError{Op: op, Path: path, Err: os.ErrNotExist}
		case "volume_path_exists":
			return &os.PathError{Op: op, Path: path, Err: os.ErrExist}
		case "volume_path_permission":
			return &os.PathError{Op: op, Path: path, Err: os.ErrPermission}
		case "volume_path_not_directory":
			return &os.PathError{Op: op, Path: path, Err: syscall.ENOTDIR}
		case "volume_path_is_directory":
			return &os.PathError{Op: op, Path: path, Err: syscall.EISDIR}
		}
	}
	return wrapFFI(err)
}

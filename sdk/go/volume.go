package microsandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Volume is persistent storage with retained destination and stable identity.
// Create, Get and List return this same type. Garbage collection never deletes storage.
type Volume struct {
	inner     *ffi.PersistentResource
	id        string
	name      string
	path      string
	kind      VolumeKind
	isDefault bool
}

// VolumeInfo is one live backend observation. Unknown usage remains nil.
type VolumeInfo struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Kind          VolumeKind        `json:"kind"`
	IsDefault     bool              `json:"is_default"`
	QuotaMiB      *uint32           `json:"quota_mib"`
	UsedBytes     *uint64           `json:"used_bytes"`
	CapacityBytes *uint64           `json:"capacity_bytes"`
	DiskFormat    *string           `json:"disk_format"`
	DiskFstype    *string           `json:"disk_fstype"`
	Labels        map[string]string `json:"-"`
	CreatedAt     *time.Time        `json:"created_at"`
}

func volumeFromResource(inner *ffi.PersistentResource) (*Volume, error) {
	var captured struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		Path      string     `json:"path"`
		Kind      VolumeKind `json:"kind"`
		IsDefault bool       `json:"is_default"`
	}
	if err := json.Unmarshal(inner.Observation, &captured); err != nil {
		return nil, err
	}
	return &Volume{inner: inner, id: captured.ID, name: captured.Name, path: captured.Path, kind: captured.Kind, isDefault: captured.IsDefault}, nil
}
func (v *Volume) ID() string       { return v.id }
func (v *Volume) Name() string     { return v.name }
func (v *Volume) Path() string     { return v.path }
func (v *Volume) Kind() VolumeKind { return v.kind }
func (v *Volume) IsDefault() bool  { return v.isDefault }
func (v *Volume) Context() Context { return contextFromNative(v.inner.Context()) }
func (v *Volume) FS() *VolumeFs    { return &VolumeFs{root: v.path, resource: v.inner} }
func (v *Volume) Info(ctx context.Context) (*VolumeInfo, error) {
	var result struct {
		VolumeInfo
		LabelPairs [][2]string `json:"labels"`
	}
	if err := v.inner.Operation(ctx, "info", nil, &result); err != nil {
		return nil, wrapFFI(err)
	}
	// Older and current native inspections serialize Rust's variant names.
	switch result.Kind {
	case "Directory":
		result.Kind = VolumeKindDir
	case "Disk":
		result.Kind = VolumeKindDisk
	}
	result.Labels = make(map[string]string, len(result.LabelPairs))
	for _, pair := range result.LabelPairs {
		result.Labels[pair[0]] = pair[1]
	}
	return &result.VolumeInfo, nil
}

// Destroy deletes only the captured identity. A same-name replacement is untouched.
func (v *Volume) Destroy(ctx context.Context) error {
	if v.isDefault {
		return &Error{Kind: ErrUnsupportedOperation, Message: "the default volume cannot be removed"}
	}
	return wrapFFI(v.inner.Operation(ctx, "destroy", nil, nil))
}

// Volumes selects persistent storage operations in one destination.
type Volumes struct{ selected Context }

func VolumeCtx(selected Context) *Volumes { return &Volumes{selected: selected} }
func (v *Volumes) Context() Context       { return v.selected }
func (v *Volumes) operation(ctx context.Context, operation, name string, args any) ([]*Volume, error) {
	destination, err := nativeDestination(v.selected)
	if err != nil {
		return nil, err
	}
	resources, err := destination.Resources(ctx, operation, name, args)
	if err != nil {
		return nil, wrapFFI(err)
	}
	volumes := make([]*Volume, len(resources))
	for i, resource := range resources {
		volumes[i], err = volumeFromResource(resource)
		if err != nil {
			return nil, err
		}
	}
	return volumes, nil
}
func oneVolume(volumes []*Volume, err error) (*Volume, error) {
	if err != nil {
		return nil, err
	}
	if len(volumes) != 1 {
		return nil, fmt.Errorf("native lookup did not return one volume")
	}
	return volumes[0], nil
}
func (v *Volumes) Create(ctx context.Context, name string, opts ...VolumeOption) (*Volume, error) {
	config := VolumeConfig{}
	for _, apply := range opts {
		apply(&config)
	}
	return oneVolume(v.operation(ctx, "volume_create", name, ffi.VolumeCreateOptions{QuotaMiB: config.QuotaMiB, Kind: string(config.Kind), SizeMiB: config.SizeMiB, Labels: config.Labels}))
}
func (v *Volumes) Get(ctx context.Context, name string) (*Volume, error) {
	return oneVolume(v.operation(ctx, "volume_get", name, nil))
}
func (v *Volumes) GetDefault(ctx context.Context) (*Volume, error) {
	return oneVolume(v.operation(ctx, "volume_get_default", "", nil))
}
func (v *Volumes) List(ctx context.Context) ([]*Volume, error) {
	return v.operation(ctx, "volume_list", "", nil)
}
func (v *Volumes) Remove(ctx context.Context, name string) error {
	_, err := v.operation(ctx, "volume_remove", name, nil)
	return err
}

func CreateVolume(ctx context.Context, name string, opts ...VolumeOption) (*Volume, error) {
	selected, err := configuredContext()
	if err != nil {
		return nil, err
	}
	return selected.Volumes().Create(ctx, name, opts...)
}
func GetVolume(ctx context.Context, name string) (*Volume, error) {
	selected, err := configuredContext()
	if err != nil {
		return nil, err
	}
	return selected.Volumes().Get(ctx, name)
}
func GetDefaultVolume(ctx context.Context) (*Volume, error) {
	selected, err := configuredContext()
	if err != nil {
		return nil, err
	}
	return selected.Volumes().GetDefault(ctx)
}
func ListVolumes(ctx context.Context) ([]*Volume, error) {
	selected, err := configuredContext()
	if err != nil {
		return nil, err
	}
	return selected.Volumes().List(ctx)
}
func RemoveVolume(ctx context.Context, name string) error {
	selected, err := configuredContext()
	if err != nil {
		return err
	}
	return selected.Volumes().Remove(ctx, name)
}

// ---------------------------------------------------------------------------
// VolumeFs — direct file operations on a volume
// ---------------------------------------------------------------------------

// VolumeFs provides direct file operations on a volume. Local operations use
// the host directory; Cloud operations use the authenticated Cloud API.
// Obtain via Volume.FS().
//
// All path arguments are relative to the volume root. Paths that would
// escape the root via "..", absolute components, or symlink chains are
// rejected with ErrPathEscape.
type VolumeFs struct {
	resource *ffi.PersistentResource
	root     string
	target   string
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
	var err error
	if fs.resource != nil {
		err = fs.resource.Operation(ctx, "fs_"+strings.TrimPrefix(op, "local_"), args, result)
	} else {
		err = ffi.VolumeFsOp(ctx, target, op, args, result)
	}
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

package microsandbox

import (
	"context"
	"time"
)

// SandboxFs provides filesystem operations for a sandbox.
// Obtain via Sandbox.FS().
type SandboxFs struct {
	sandbox *Sandbox
}

// FsEntry represents a directory entry in the sandbox.
type FsEntry struct {
	Path string
	Kind string // "file", "dir", "symlink"
	Size int64
	Mode uint32
}

// FsStat represents file metadata in the sandbox.
type FsStat struct {
	Path    string
	Size    int64
	Mode    uint32
	ModTime time.Time
	IsDir   bool
}

// Read reads the contents of a file from the sandbox.
func (fs *SandboxFs) Read(ctx context.Context, path string) ([]byte, error) {
	if fs.sandbox == nil {
		return nil, NewError(ErrInvalidConfig, "sandbox is nil")
	}
	return fs.sandbox.ffi.FSRead(ctx, fs.sandbox.handle, path)
}

// ReadString reads the contents of a file from the sandbox as a string.
func (fs *SandboxFs) ReadString(ctx context.Context, path string) (string, error) {
	data, err := fs.Read(ctx, path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Write writes data to a file in the sandbox.
func (fs *SandboxFs) Write(ctx context.Context, path string, data []byte) error {
	if fs.sandbox == nil {
		return NewError(ErrInvalidConfig, "sandbox is nil")
	}
	return fs.sandbox.ffi.FSWrite(ctx, fs.sandbox.handle, path, data)
}

// WriteString writes a string to a file in the sandbox.
func (fs *SandboxFs) WriteString(ctx context.Context, path string, content string) error {
	return fs.Write(ctx, path, []byte(content))
}

// List lists the contents of a directory in the sandbox.
func (fs *SandboxFs) List(ctx context.Context, path string) ([]FsEntry, error) {
	if fs.sandbox == nil {
		return nil, NewError(ErrInvalidConfig, "sandbox is nil")
	}
	entries, err := fs.sandbox.ffi.FSList(ctx, fs.sandbox.handle, path)
	if err != nil {
		return nil, err
	}

	result := make([]FsEntry, len(entries))
	for i, e := range entries {
		result[i] = FsEntry{
			Path: e.Path,
			Kind: e.Kind,
			Size: e.Size,
			Mode: e.Mode,
		}
	}
	return result, nil
}

// Stat retrieves metadata for a file or directory in the sandbox.
func (fs *SandboxFs) Stat(ctx context.Context, path string) (*FsStat, error) {
	if fs.sandbox == nil {
		return nil, NewError(ErrInvalidConfig, "sandbox is nil")
	}
	stat, err := fs.sandbox.ffi.FSStat(ctx, fs.sandbox.handle, path)
	if err != nil {
		return nil, err
	}

	return &FsStat{
		Path:    stat.Path,
		Size:    stat.Size,
		Mode:    stat.Mode,
		ModTime: stat.ModTime,
		IsDir:   stat.IsDir,
	}, nil
}

// CopyIn copies a file from the host into the sandbox.
func (fs *SandboxFs) CopyIn(ctx context.Context, hostPath, guestPath string) error {
	if fs.sandbox == nil {
		return NewError(ErrInvalidConfig, "sandbox is nil")
	}
	return fs.sandbox.ffi.FSCopyIn(ctx, fs.sandbox.handle, hostPath, guestPath)
}

// CopyOut copies a file from the sandbox to the host.
func (fs *SandboxFs) CopyOut(ctx context.Context, guestPath, hostPath string) error {
	if fs.sandbox == nil {
		return NewError(ErrInvalidConfig, "sandbox is nil")
	}
	return fs.sandbox.ffi.FSCopyOut(ctx, fs.sandbox.handle, guestPath, hostPath)
}
